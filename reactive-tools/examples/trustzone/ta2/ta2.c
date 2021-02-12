#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <tee_internal_api.h>

#include <ta2.h>

#define SIZE_OF_VEC(vec) (sizeof(vec) - 1)

uint8_t modulus[] =
"\xbe\x5c\xe7\x5f\xef\xd6\x8b\x23\xaf\x9f\xa5\x44\xfc\xa4\x9a"
"\x94\x0a\xc8\x67\x57\x30\x6d\x20\x4b\xa0\xee\xd6\x5f\x07\x9b"
"\x4a\x98\x5d\xcf\x9a\xce\xae\xaa\xa9\x9b\xeb\xdf\xdc\xde\xb9"
"\xfc\x3f\x54\xb2\x93\x7d\xe2\x9e\x29\x52\x57\xd4\x3d\xbc\x4c"
"\x89\xa7\xe9\xc5";

uint8_t public_key[] =
"\x01\x00\x01";

uint8_t private_key[] = 
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00";

//=========================================================

void *malloc_aligned(size_t size) {
  size += size % 2;

  return malloc(size);
}

int total_node = 0;

typedef struct
{
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

   printf("@@@@@@@@ inside add_connection @@@@@@\n");
   for (int j = 0; j < 16; j++){
	   printf("%02X", connection->connection_key[j]);
   }

   node->connection = *connection;
   node->next = connections_head;
   connections_head = node;
   return 1;
}

Connection* connections_get(uint16_t conn_id)
{
	printf("$$$$$$$$ inside of get_connections func $$$$$$$\n");
    Node* current = connections_head;

    while (current != NULL) {
        Connection* connection = &current->connection;

        if (connection->conn_id == conn_id) {
			for (int j = 0; j < 16; j++)
		   		printf("%02X", connection->connection_key[j]);
            return connection;
        }

        current = current->next;
    }

    return NULL;
}

void find_connections(uint16_t io_id, int *arr, uint8_t *num)
{
	printf("%%%%%%%%%%%% inside of find_connections func %%%%%%%%%\n");
    Node* current = connections_head;

    while (current != NULL) {
        Connection* connection = &current->connection;

        if (connection->io_id == io_id) {
            arr[*num] = connection->conn_id;
			printf("conn_id %d\n", arr[*num]);
            *num = *num + 1;
        }

        current = current->next;
    }

}

//=========================================================

char module_key[16] = { 0 };

struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
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
	
	printf("//--------------KEY-----------------------\n");
	for (int j = 0; j < 16; j++)
		printf("%02X", key[j]);


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
                     char *nonce, size_t nonce_sz){
	
	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: reset initial vector", session);
	sess = (struct aes_cipher *)session;

	printf("//--------------aaaaaaaadddddd-----------------------\n");
	for (int j = 0; j < aad_sz; j++)
		printf("%02X", aad[j]);
	printf("\n");
	for (int j = 0; j < nonce_sz; j++)
		printf("%02X", nonce[j]);
	//-------------------------------------------------------------------------------
	printf("$$$$$$$$$$$$ before AEInit $$$$$$$$$$");

	TEE_AEInit(sess->op_handle, nonce, nonce_sz, 16*8/* tag_len in bits */, aad_sz /*aad_len*/,
						16 /*plaintext_len*/);
	printf("*********** after AEInit ************");

	TEE_AEUpdateAAD(sess->op_handle, aad, aad_sz);

	printf("*********** after AEUpdate ************");
	
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
    char nonce[16] = { 0 };
    size_t nonce_sz = 16;

    alloc_resources(sess, TA_AES_ALGO_GCM, 16, TA_AES_MODE_DECODE);
    set_aes_key(sess, module_key, 16);
    //memset(nonce, 0, 16); 
    reset_aes_iv(sess, params[0].memref.buffer, params[0].memref.size, nonce, nonce_sz);

    char *tag;
    tag = params[0].memref.buffer;
    char *temp;
   
    void *decrypted_key = NULL;
    void *tag_void = NULL;

   //=============================================================================== 
    decrypted_key = TEE_Malloc(16, 0);
    tag_void = TEE_Malloc(params[2].memref.size, 0);
	if (!decrypted_key || !tag_void)
		goto out;

	TEE_MemMove(tag_void, params[2].memref.buffer, params[2].memref.size);

	res = TEE_AEDecryptFinal(sess->op_handle, params[1].memref.buffer,
				 params[1].memref.size, decrypted_key, &params[2].memref.size, tag_void,
				 params[2].memref.size);

	if (!res) {
      printf("winnnnnnnnnnnnnnnnnnn\n");
      temp = decrypted_key;
      for (int j = 0; j < 16; j++){
		  connection.connection_key[j]= temp[j];
	  }
	  printf("\n");
	  for (int j = 0; j < 16; j++)
		   printf("%02X", connection.connection_key[j]);
	  printf("\n");

	  connection.nonce = 0;
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

// =======================encrypt=======================================
int encrypt_using_public_key (char * in, int in_len, char * out, int * out_len) {

   TEE_Result ret = TEE_SUCCESS; // return code
   TEE_ObjectHandle key = (TEE_ObjectHandle) NULL;
   TEE_Attribute rsa_attrs[3];
   TEE_ObjectInfo info;
   TEE_OperationHandle handle = (TEE_OperationHandle) NULL;

   // modulus
   rsa_attrs[0].attributeID = TEE_ATTR_RSA_MODULUS;
   rsa_attrs[0].content.ref.buffer = modulus;
   rsa_attrs[0].content.ref.length = SIZE_OF_VEC (modulus);
   // Public key
   rsa_attrs[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
   rsa_attrs[1].content.ref.buffer = public_key;
   rsa_attrs[1].content.ref.length = SIZE_OF_VEC (public_key);
   // Private key
   rsa_attrs[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
   rsa_attrs[2].content.ref.buffer = private_key;
   rsa_attrs[2].content.ref.length = SIZE_OF_VEC (private_key);

   // create a transient object
   ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 512, &key);
   if (ret != TEE_SUCCESS) {
      return TEE_ERROR_BAD_PARAMETERS;
   }

   // populate the object with your keys
   ret = TEE_PopulateTransientObject(key, (TEE_Attribute *)&rsa_attrs, 3);
   printf("=======================Im here ============================");
   if (ret != TEE_SUCCESS) {
      return TEE_ERROR_BAD_PARAMETERS;
   }
   // setup the info structure about the key
   TEE_GetObjectInfo (key, &info);

   // Allocate the operation
   ret = TEE_AllocateOperation (&handle, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, info.maxObjectSize);
   if (ret != TEE_SUCCESS) {
      return 0;
   }

   // set the key
   ret = TEE_SetOperationKey(handle, key);
   if (ret != TEE_SUCCESS) {
      TEE_FreeOperation(handle);
      return 0;
   }

   void * to_encrypt = NULL;
   uint32_t cipher_len = 256;
   void * cipher = NULL;
   // create your structures to de / encrypt
   to_encrypt = TEE_Malloc (in_len, 0);
   cipher = TEE_Malloc (cipher_len, 0);
   if (!to_encrypt || !cipher) {
      return TEE_ERROR_BAD_PARAMETERS;
   }
   TEE_MemMove(to_encrypt, in, in_len);
   // encrypt
   printf("Godddd\n");
   ret = TEE_AsymmetricEncrypt (handle, (TEE_Attribute *)NULL, 0, 
                                 to_encrypt, in_len, cipher, &cipher_len);
   printf("fuckk\n");
   if (ret != TEE_SUCCESS) {
      TEE_FreeOperation(handle);
      return 0;
   }

   // finish off
   memcpy (out, cipher, cipher_len);
   *out_len = cipher_len;
   out[cipher_len] = '\0';

   // clean up after yourself
   TEE_FreeOperation(handle);
   TEE_FreeTransientObject (key);
   TEE_Free (cipher);
   TEE_Free(to_encrypt);

   // finished
   return 0;
}

TEE_Result encrypt_module_key(TEE_Param params[4]) {
	void *buf = NULL;
	buf = TEE_Malloc(16, 0);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_GenerateRandom(buf, 16);
	TEE_MemMove(module_key, buf, 16);
	printf("//--------------Module key--------------------------\n");
    for (int j = 0; j < 16; j++)
		printf("%02X", module_key[j]);
	TEE_Free(buf);
//======================================================
   // will be encrypted into here
   char encrypted [256];
   int encrypted_len;

   DMSG("<<<<<<<<<<<<<<<<<<<<<<<<<<< test_encrypt_ta >>>>>>>>>>>>>>>>>>>>>>>>> ");
   encrypt_using_public_key (module_key, sizeof(module_key), encrypted, &encrypted_len);
   memcpy(params[0].memref.buffer, encrypted, encrypted_len);
   params[0].memref.size = encrypted_len;    
   //params[2].value.a = 0;
   DMSG ("SW Encryted value:   %s", encrypted);
   DMSG ("SW Encryted len:     %i", encrypted_len);
   DMSG("<<<<<<<<<<<<<<<<<<<<<<<<<<< end of test >>>>>>>>>>>>>>>>>>>>>>>>> ");
   return TEE_SUCCESS;

}
//======================================================================

void input(char *data){
	printf("\n");
	printf("Button is Pressed in TA1\n");
}

TEE_Result handle_input(void *session, uint32_t param_types, TEE_Param params[4]){

	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE);

	printf("^^^^^^^^^^^^^inside handle_output fun^^^^^^^^^^^^^\n");
	TEE_Result res;
	struct aes_cipher *sess;
	sess = (struct aes_cipher *)session;

	printf("conn_id : %d\n", params[0].value.a);
	Connection* connection = connections_get(params[0].value.a);

	char nonce[16] = { 0 };
    size_t nonce_sz = 16;

	unsigned char aad[2] = { 0 };
	int j = 1;
    for(int m = 0; m < 2; m++){
    	aad[m] = ((connection->nonce) >> (8*j)) & 0xFF; // ########
    	j--;
    }
	alloc_resources(sess, TA_AES_ALGO_GCM, 16, TA_AES_MODE_DECODE);
    set_aes_key(sess, connection->connection_key, 16); //#######
    reset_aes_iv(sess, aad, 2, nonce, nonce_sz);

	char *temp;
    void *decrypted_data = NULL;
    void *tag_void = NULL;

    decrypted_data = TEE_Malloc(16, 0);
    tag_void = TEE_Malloc(params[2].memref.size, 0);
	if (!decrypted_data || !tag_void)
		goto out;

	TEE_MemMove(tag_void, params[2].memref.buffer, params[2].memref.size);

	res = TEE_AEDecryptFinal(sess->op_handle, params[1].memref.buffer,
				 params[1].memref.size, decrypted_data, &params[2].memref.size, tag_void,
				 params[2].memref.size);

	if (!res) {
      printf("winnnnnnn to decrypt data\n");
      temp = decrypted_data;
	  for(int i=0; i<16; i++){
		  printf("%2X",temp[i]);
	  }
	  connection->nonce = connection->nonce + 1;
	  switch (connection->io_id)
	  {
	  case 4:
		  input(temp);
		  break;
	  
	  default:
		  break;
	  }
	}
out:
	TEE_Free(decrypted_data);
	TEE_Free(tag_void);

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
	printf("#################Invoking#############################\n");
	switch (cmd) {
    case ENCRYPT_MODULE_KEY_IN_TA_COMMAND:
    	return encrypt_module_key(params);
	case SET_KEY:
		return set_key(session, param_types, params);
	case HANDLE_INPUT:
		return handle_input(session, param_types, params);
	case ENTRY:
		return TEE_SUCCESS;
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}