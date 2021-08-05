#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <tee_internal_api.h>

#include <tee_isocket.h>
#include <tee_tcpsocket.h>
#include <tee_udpsocket.h>

#include <button_driver.h>
#include <authentic_execution.h>
#include <pta_attestation.h>
#include <spongent.h>

static const TEE_UUID pta_attestation_uuid = ATTESTATION_UUID;

void *malloc_aligned(size_t size) {
  size += size % 2;

  return malloc(size);
}

int total_node = 0;

typedef struct
{
    uint8_t  encryption;
	uint16_t conn_id;
    uint16_t io_id;
    uint16_t nonce;
    unsigned char connection_key[16];
} Connection;

typedef struct Node
{
    Connection connection;
    struct Node* next;
} Node;

static Node* connections_head = NULL;

int connections_add(Connection* connection)
{
   Node* node = malloc_aligned(sizeof(Node));

   if (node == NULL)
      return 0;

   node->connection = *connection;
   node->next = connections_head;
   connections_head = node;
   return 1;
}

Connection* connections_get(uint16_t conn_id)
{
    Node* current = connections_head;

    while (current != NULL) {
        Connection* connection = &current->connection;

        if (connection->conn_id == conn_id) {
            return connection;
        }

        current = current->next;
    }

    return NULL;
}

void find_connections(uint16_t io_id, int *arr, uint8_t *num)
{
    Node* current = connections_head;
    while (current != NULL) {
        Connection* connection = &current->connection;
        if (connection->io_id == io_id) {
            arr[*num] = connection->conn_id;
            *num = *num + 1;
        }

        current = current->next;
    }

}

//===============================================================

char module_key[16] = { 0 };

struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

struct sock_handle {
	TEE_iSocketHandle ctx;
	TEE_iSocket *socket;
};
//===============================================================

static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo)
{
	switch (param) {
	case TA_AES_ALGO_ECB:
		*algo = TEE_ALG_AES_ECB_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CBC:
		*algo = TEE_ALG_AES_CBC_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_GCM:
		*algo = TEE_ALG_AES_GCM;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid algo %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size)
{
	switch (param) {
	case 16:
		*key_size = param;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid key size %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode)
{
	switch (param) {
	case TA_AES_MODE_ENCODE:
		*mode = TEE_MODE_ENCRYPT;
		return TEE_SUCCESS;
	case TA_AES_MODE_DECODE:
		*mode = TEE_MODE_DECRYPT;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid mode %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result alloc_resources(void *session, uint32_t algo, uint32_t key_size,
                                    uint32_t mode){

	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;
	char *key;

	/* Get ciphering context from session ID */
	DMSG("Session %p: get ciphering resources", session);
	sess = (struct aes_cipher *)session;

	res = ta2tee_algo_id(algo, &sess->algo);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_key_size(key_size, &sess->key_size);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_mode_id(mode, &sess->mode);
	if (res != TEE_SUCCESS)
		return res;

	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(&sess->op_handle,
				    sess->algo,
				    sess->mode,
				    sess->key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		sess->op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Free potential previous transient object */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
					  sess->key_size * 8,
					  &sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		sess->key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	key = TEE_Malloc(sess->key_size, 0);
	if (!key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto err;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		goto err;
	}

	return res;

err:
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	sess->op_handle = TEE_HANDLE_NULL;

	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	sess->key_handle = TEE_HANDLE_NULL;

	return res;
}

static TEE_Result set_aes_key(void *session, char *key, uint32_t key_sz){

	struct aes_cipher *sess;
	TEE_Attribute attr;
	TEE_Result res;

	/* Get ciphering context from session ID */
	DMSG("Session %p: load key material", session);
	sess = (struct aes_cipher *)session;

	//---------------------------------------------------------------
	if (key_sz != sess->key_size) {
		EMSG("Wrong key size %" PRIu32 ", expect %" PRIu32 " bytes",
		     key_sz, sess->key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_sz);

	TEE_ResetTransientObject(sess->key_handle);
	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}

	return res;
}

static TEE_Result reset_aes_iv(void *session, char *aad, size_t aad_sz,
                     char *nonce, size_t nonce_sz, size_t payload_sz){

	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: reset initial vector", session);
	sess = (struct aes_cipher *)session;

	TEE_AEInit(sess->op_handle, nonce, nonce_sz, 16*8/* tag_len in bits */, aad_sz /*aad_len*/,
						payload_sz /*plaintext_len*/);

	TEE_AEUpdateAAD(sess->op_handle, aad, aad_sz);

	return TEE_SUCCESS;
}

static TEE_Result set_key(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
    Connection connection;

	DMSG("Session %p: cipher buffer", session);
	sess = (struct aes_cipher *)session;
    char nonce[12] = { 0 };
    size_t nonce_sz = 12;

    alloc_resources(sess, TA_AES_ALGO_GCM, 16, TA_AES_MODE_DECODE);
    set_aes_key(sess, module_key, 16);
    reset_aes_iv(sess, params[0].memref.buffer, params[0].memref.size, nonce, nonce_sz, params[1].memref.size);

    char *tag;
    tag = params[0].memref.buffer;
    char *temp;

    void *decrypted_key = NULL;
    void *tag_void = NULL;

   //==========================================
    decrypted_key = TEE_Malloc(16, 0);
    tag_void = TEE_Malloc(params[2].memref.size, 0);
	if (!decrypted_key || !tag_void)
		goto out;

	TEE_MemMove(tag_void, params[2].memref.buffer, params[2].memref.size);

	res = TEE_AEDecryptFinal(sess->op_handle, params[1].memref.buffer,
				 params[1].memref.size, decrypted_key, &params[2].memref.size, tag_void,
				 params[2].memref.size);

	if (!res) {
      temp = decrypted_key;
      for (int j = 0; j < 16; j++){
		  connection.connection_key[j]= temp[j];
	  }

	  connection.nonce = 0;
	  connection.encryption = tag[0] & 0xFF;

	  int j = 0;
      connection.conn_id = 0;
      for(int n=2; n>=1; --n){
         connection.conn_id = connection.conn_id + (( tag[n] & 0xFF ) << (8*j));
         ++j;
      }
      j = 0;
      connection.io_id = 0;
      for(int n=4; n>=3; --n){
         connection.io_id = connection.io_id + (( tag[n] & 0xFF ) << (8*j));
         ++j;
      }
	  total_node = total_node + 1;
      connections_add(&connection);
    }

out:
	TEE_Free(decrypted_key);
    TEE_Free(tag_void);

	return res;
}

//======================================================================

static TEE_Result attest(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;

	DMSG("Session %p: cipher buffer", session);
	sess = (struct aes_cipher *)session;

	// ------------ Call PTA ---------**************************************************
	TEE_TASessionHandle pta_session = TEE_HANDLE_NULL;
	uint32_t ret_origin = 0;
	uint32_t pta_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_OUTPUT,
											TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
											TEE_PARAM_TYPE_NONE);

	TEE_Param pta_params[TEE_NUM_PARAMS];

	// prepare the parameters for the pta
	pta_params[0].memref.buffer = module_key;
	pta_params[0].memref.size = 16;

	// ------------ Open Session to PTA ---------
	res = TEE_OpenTASession(&pta_attestation_uuid, 0, 0, NULL, &pta_session,
				&ret_origin);
	if (res != TEE_SUCCESS)
		return res;

	// ------------ Invoke command at PTA (get_module key) ---------
	res = TEE_InvokeTACommand(pta_session, 0, ATTESTATION_CMD_GET_MODULE_KEY,
								pta_param_types, pta_params, &ret_origin);
	if (res != TEE_SUCCESS)
		return res;

	// ------------ Close Session to PTA ---------
	TEE_CloseTASession(pta_session);

	//*******************************************************************************
    char nonce[12] = { 0 };
    size_t nonce_sz = 12;
	// challenge =  param[0] --> aad
    alloc_resources(sess, TA_AES_ALGO_GCM, 16, TA_AES_MODE_ENCODE);
    set_aes_key(sess, module_key, 16);
    reset_aes_iv(sess, params[0].memref.buffer, params[0].memref.size, nonce, nonce_sz, 0);

	unsigned char challenge[16]={0};
	memcpy(challenge, params[0].memref.buffer, 16);
    DMSG("Module key: %x %x", module_key[0], module_key[1]);
    DMSG("Challenge: %x %x", challenge[0], challenge[1]);

    void *tag = TEE_Malloc(16, 0);
    uint32_t len = 0, tag_len = 16;

	res = TEE_AEEncryptFinal(sess->op_handle, NULL,
				 0, NULL, &len, tag, &tag_len);

	if (!res) {
		params[1].memref.size = 16;
		TEE_MemMove(params[1].memref.buffer, tag, params[1].memref.size);
    }
    else {
    	DMSG("MAC generation failed: %d", res);
    }

	TEE_Free(tag);

	return res;

}


//======================================================================

void handle_output(void *session, unsigned char *data, uint32_t data_len, 
															uint16_t output_id){
	
	struct aes_cipher *sess;
	sess = (struct aes_cipher *)session;

	TEE_Result res;
	//uint32_t data_len = params[0].value.a;
	uint8_t num = 0;
	BitSequence output[data_len];
	BitSequence f_tag[16]; 	

	void *conn_id_buf;
	void *encrypt_buf;
	void *tag_buf;

	int arr[total_node];
	find_connections(output_id, arr, &num);
	//params[0].value.a = num;
	conn_id_buf = TEE_Malloc(num * 2, 0);
	encrypt_buf = TEE_Malloc(num * data_len, 0);
	tag_buf = TEE_Malloc(num * 16, 0);

	//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
	struct sock_handle h = { };
	TEE_tcpSocket_Setup setup = { };
	uint32_t sock_err;
	setup.ipVersion = TEE_IP_VERSION_4;
	setup.server_port = 1236;
	char addr[] = "127.0.0.1";
	setup.server_addr = strndup(addr, strlen(addr));
	if (!setup.server_addr){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	
	h.socket = TEE_tcpSocket;
	res = h.socket->open(&h.ctx, &setup, &sock_err);
	free(setup.server_addr); //?
	if (res == TEE_SUCCESS) {
		printf("++++++++++++++ connectiom to em ++++++++++++\n");
	}
	//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

	for(int i=0; i<num; i++) {

		Connection* connection = connections_get(arr[i]);
		char nonce[12] = { 0 };
    	size_t nonce_sz = 12;

		unsigned char aad[2] = { 0 };
		int j = 1;
    	for(int m = 0; m < 2; m++){
    		aad[m] = ((connection->nonce) >> (8*j)) & 0xFF; // ########
    		j--;
    	}

		//*************** ^ ^ *******************************************************

		if(connection->encryption == AES){
    		alloc_resources(sess, TA_AES_ALGO_GCM, 16, TA_AES_MODE_ENCODE);
    		set_aes_key(sess, connection->connection_key, 16); //#######
    		reset_aes_iv(sess, aad, 2, nonce, nonce_sz, data_len);

			void *encrypt = NULL;
			void *tag = NULL;
			uint32_t sz = 16;

			encrypt = TEE_Malloc(data_len, 0);
			tag = TEE_Malloc(16, 0);

    		const void *text = data;
			printf("data_len: %d\n", data_len);
			for (int n = 0; n < data_len; n++){
		  		printf("%02x ", data[n]);
			}
			memcpy(data, text, data_len);
			for (int n = 0; n < data_len; n++){
		  		printf("%02x ", data[n]);
			}
			//text = TEE_Malloc(data_len, 0);
			//text = data;
			//memcpy(text, params[2].memref.buffer, data_len);
			printf("hellooooooo###############\n");
			res = TEE_AEEncryptFinal(sess->op_handle, text, data_len,
					encrypt, &data_len, tag, &sz);

			printf("afterrrrrrrrrrrrrrrrrrrrrrrrrrr\n");		

			if (!res) {
				memcpy(output, encrypt, data_len);
				memcpy(f_tag, tag, 16);
				TEE_Free(encrypt);
    			TEE_Free(tag);
				//TEE_Free(text);
			}
		}//if AES
		else {
			//SPONGENT for Sancus	
			SpongentWrap(connection->connection_key, aad, 16, data, data_len * 8, output, f_tag, 0);
		}//if Spongent
		// Create packet for sending to EM ++++++++++++++++++++++++++++++++++++++++++++++
		unsigned char payload[100] = {0};

		unsigned char conn_id_array[2] = { 0 };
		int c = 1;
    	for(int m = 0; m < 2; m++){
    		conn_id_array[m] = ((connection->conn_id) >> (8*c)) & 0xFF; // ########
    		c--;
    	}
		unsigned char payload_size[2] = { 0 };
		c = 1;
		for(int m = 0; m < 2; m++){
    		conn_id_array[m] = ((2 + data_len + 16) >> (8*c)) & 0xFF; // //conn id + encrypt + tag
    		c--;
    	}

    	payload[0] = "\x04";
    	memcpy(payload + 1, payload_size, 2);
    	memcpy(payload + 3, conn_id_array, 2);
    	memcpy(payload + 5, output, data_len);
    	memcpy(payload + 5 + data_len, f_tag, 16);

		void *buf = NULL;
		buf = TEE_Malloc ((21 + data_len), 0);
		TEE_MemMove(buf, payload, (21 + data_len)); 
		size_t blen = sizeof(buf);
	
		res = h.socket->send(h.ctx, buf, &blen , TEE_TIMEOUT_INFINITE);

		if (res == TEE_SUCCESS) {
			printf("yesssss sent to the em\n");
		}

		res = h.socket->recv(h.ctx, buf, &blen, TEE_TIMEOUT_INFINITE);
		if (res == TEE_SUCCESS) {
			printf("receive something from EM\n");
		}
		//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

		connection->nonce = connection->nonce + 1; //######

    } // for
	// close connection with EM
	h.socket->close(h.ctx);
	/*params[1].memref.size = 2*num;
	TEE_MemMove(params[1].memref.buffer, conn_id_buf, params[1].memref.size);
	params[2].memref.size = data_len * num;
	TEE_MemMove(params[2].memref.buffer, encrypt_buf, params[2].memref.size);
	params[3].memref.size = 16*num;
	TEE_MemMove(params[3].memref.buffer, tag_buf, params[3].memref.size);

	TEE_Free(conn_id_buf);
	TEE_Free(encrypt_buf);
	TEE_Free(tag_buf);*/
}

//=========================================================================
TEE_Result handle_input(void *session, uint32_t param_types, TEE_Param params[4]){

	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE);

	TEE_Result res;
	struct aes_cipher *sess;
	sess = (struct aes_cipher *)session;
	unsigned char* data;
	data = malloc(params[1].memref.size);

	Connection* connection = connections_get(params[0].value.a);

	char nonce[12] = { 0 };
    size_t nonce_sz = 12;

	unsigned char aad[2] = { 0 };
	int j = 1;
    for(int m = 0; m < 2; m++){
    	aad[m] = ((connection->nonce) >> (8*j)) & 0xFF; // ########
    	j--;
    }

	//---------------------------------------------------------------
	if(connection->encryption == AES){
		alloc_resources(sess, TA_AES_ALGO_GCM, 16, TA_AES_MODE_DECODE);
    	set_aes_key(sess, connection->connection_key, 16); //#######
    	reset_aes_iv(sess, aad, 2, nonce, nonce_sz, params[1].memref.size);

    	void *decrypted_data = NULL;
    	void *tag_void = NULL;

    	decrypted_data = TEE_Malloc(params[1].memref.size, 0);
    	tag_void = TEE_Malloc(params[2].memref.size, 0);

		TEE_MemMove(tag_void, params[2].memref.buffer, params[2].memref.size);

		res = TEE_AEDecryptFinal(sess->op_handle, params[1].memref.buffer,
				 params[1].memref.size, decrypted_data, &params[1].memref.size, tag_void,
				 params[2].memref.size);

		if (!res) {
      		data = decrypted_data;
	  		for(int i = 0; i <  params[1].memref.size; i++){
		  		printf("%2X", data[i]);
	  		}
	  		TEE_Free(decrypted_data);
	  		TEE_Free(tag_void);
		}
	}
	else{

		BitSequence tag_spongent[16]; 	// TAG length is the same as the key length. 16 bytes.
		BitSequence encrypted_data[params[1].memref.size];

		for (int n = 0; n < params[1].memref.size; n++){
			encrypted_data[n] = ((uint8_t *)params[1].memref.buffer)[n];
		}

		for (int n = 0; n < 16; n++){
			tag_spongent[n] = ((uint8_t *)params[2].memref.buffer)[n];
		}

		SpongentUnwrap(connection->connection_key, aad, 16, encrypted_data,
										(params[1].memref.size) * 8, data, tag_spongent);

		for(int i = 0; i < params[1].memref.size; i++){
			printf("%2X", data[i]);
	  	}

	}

	connection->nonce = connection->nonce + 1;

	find_input_func(connection->io_id, data);

	return TEE_SUCCESS;
}

// Called when the TA is created =======================================
TEE_Result TA_CreateEntryPoint(void) {
   DMSG("=============== TA_CreateEntryPoint ================");
   return TEE_SUCCESS;
}

// Called when the TA is destroyed
void TA_DestroyEntryPoint(void) {
   DMSG("=============== TA_DestroyEntryPoint ===============");
}

// open session
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session)
{
   DMSG("=========== TA_OpenSessionEntryPoint ===============");

	struct aes_cipher *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

// close session
void TA_CloseSessionEntryPoint(void *session)
{
   DMSG("========== TA_CloseSessionEntryPoint ===============");

	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct aes_cipher *)session;

	/* Release the session resources */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

// invoke command
TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd, uint32_t param_types,
					TEE_Param params[4])
{
	DMSG("^^^^^^^^^^^^^^^^Invoking^^^^^^^^^^^^^^^^^^^\n");
	switch (cmd) {
	case SET_KEY:
		return set_key(session, param_types, params);
	case ATTEST:
		return attest(session, param_types, params);
	case HANDLE_INPUT:
		return handle_input(session, param_types, params);
	case ENTRY:
		return entry(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
