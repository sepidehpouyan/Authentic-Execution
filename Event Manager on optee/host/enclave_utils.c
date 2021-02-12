#include "enclave_utils.h"

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h> 

/* OP-TEE TEE client API (built by optee_client) */
#include "tee_client_api.h"

//#include "byteorder.h"
#include "addr.h"
#include "networking.h"
#include "command_handlers.h"
#include "utils.h"
#include "connection.h"

#define LOCAL_RANDOM_PORT 1235

//------------------------------------------------------------------------------------------
/* TEE resources */
uint16_t node_number = 1;

typedef struct
{
  TEEC_UUID uuid;
	TEEC_Context ctx;
	TEEC_Session sess;
  TEEC_Operation op;
} TA_CTX;

typedef struct CTX_Node
{
    TA_CTX ta_ctx;
    struct CTX_Node* next;
} CTX_Node;

static CTX_Node* ta_ctx_head = NULL;

int ta_ctx_add(TA_CTX* ta_ctx)
{
    CTX_Node* node = malloc_aligned(sizeof(CTX_Node));

    if (node == NULL)
        return 0;

    node->ta_ctx = *ta_ctx;
    node->next = ta_ctx_head;
    ta_ctx_head = node;
    return 1;
}

TA_CTX* ta_ctx_get(TEEC_UUID uuid)
{
    CTX_Node* current = ta_ctx_head;

    while (current != NULL) {
        TA_CTX* ctx = &current->ta_ctx;

        if ((ctx->uuid.timeLow == uuid.timeLow) &&
            (ctx->uuid.timeMid == uuid.timeMid) &&
            (ctx->uuid.timeHiAndVersion == uuid.timeHiAndVersion) &&
            !memcmp(ctx->uuid.clockSeqAndNode, uuid.clockSeqAndNode, 8)) {

            return ctx;
        }

        current = current->next;
    }

    return NULL;
}
//---------------------------------------------------------------------------------------
void check_rc (TEEC_Result rc, const char *errmsg, uint32_t *orig) {

   printf("rc numebr %x\n", rc);
   if (rc != TEEC_SUCCESS) {
      fprintf(stderr, "%s: 0x%08x", errmsg, rc);
      if (orig)
      fprintf(stderr, " (orig=%d)", (int)*orig);
      fprintf(stderr, "\n");

      exit(1);
   }
}

TEEC_UUID get_uuid (unsigned char* buf){

  TEEC_UUID uuid;

  int j = 0;
  int timelow = 0;
  for(int m = 3; m >= 0; --m){
    timelow = timelow + (( buf[m] & 0xFF ) << (8*j));
    ++j;
  }	
  uuid.timeLow = timelow;

//-----------------------------------------------

  j = 0;
  int mid = 0;
  for(int m = 5; m>=4; --m){
    mid = mid + (( buf[m] & 0xFF ) << (8*j));
    ++j;
  }	
  uuid.timeMid = mid;

//-------------------------------------------------------------

  j = 0;
  int high = 0;
  for(int m = 7; m>=6; --m){
    high = high + (( buf[m] & 0xFF ) << (8*j));
    ++j;
  }	
  uuid.timeHiAndVersion = high;

  ///------------------------------------------------------------------------------

  for(int m = 8; m < 16; m++){
    uuid.clockSeqAndNode[m-8] = buf[m];
  }
  return uuid;
}

ResultMessage load_enclave(unsigned char* buf, uint32_t size) {

  TA_CTX ctx;
  TEEC_Result rc;
  TEEC_SharedMemory field_back;
  uint32_t err_origin;

  ctx.uuid = get_uuid(buf);

  char fname[255] = { 0 };
	FILE *file = NULL;
  char path[] = "/lib/optee_armtz";

  snprintf(fname, PATH_MAX,
		     "%s/%08x-%04x-%04x-%02x%02x%s%02x%02x%02x%02x%02x%02x.ta",
         path,
		     ctx.uuid.timeLow,
		     ctx.uuid.timeMid,
		     ctx.uuid.timeHiAndVersion,
		     ctx.uuid.clockSeqAndNode[0],
		     ctx.uuid.clockSeqAndNode[1],
		     "-",
		     ctx.uuid.clockSeqAndNode[2],
		     ctx.uuid.clockSeqAndNode[3],
		     ctx.uuid.clockSeqAndNode[4],
		     ctx.uuid.clockSeqAndNode[5],
		     ctx.uuid.clockSeqAndNode[6],
		     ctx.uuid.clockSeqAndNode[7]);
  
  //printf("%s", fname);
  
  file = fopen(fname, "w"); 
  
  fwrite(buf + 16 ,1, size - 16 , file);
  fclose(file); 

/* Initialize a context connecting us to the TEE */
  rc = TEEC_InitializeContext(NULL, &ctx.ctx);
  check_rc(rc, "TEEC_InitializeContext", NULL);

// open a session to the TA
  printf("ctx.fd: %d sess.id %d and %d\n", ctx.ctx.fd, ctx.sess.session_id, ctx.uuid.timeLow);
  rc = TEEC_OpenSession(&ctx.ctx, &ctx.sess, &ctx.uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
  check_rc(rc, "TEEC_OpenSession", &err_origin);

// ok, create the needed shared memory blocks we will be using later
  field_back.buffer = NULL;
  field_back.size = 256;
  field_back.flags = TEEC_MEM_OUTPUT;
  rc = TEEC_AllocateSharedMemory(&ctx.ctx, &field_back);
  check_rc(rc, "TEEC_AllocateSharedMemory for field_back", NULL);

/* Clear the TEEC_Operation struct */
  memset(&ctx.op, 0, sizeof(ctx.op));

// assign param
  ctx.op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, 
                                    TEEC_NONE, TEEC_NONE);
  
  ctx.op.params[0].memref.parent = &field_back;

// prepare for encrypt
  printf("before invoke value: %d and %d and %d\n", ctx.ctx.fd, ctx.sess.session_id, ctx.uuid.timeLow);
  printf("context in sesssion %p\n", ctx.sess.ctx);
  rc = TEEC_InvokeCommand(&ctx.sess, 0, &ctx.op, &err_origin);
  check_rc(rc, "TEEC_InvokeCommand", &err_origin);

  
  size_t response_size = (int) ctx.op.params[0].memref.size;
  unsigned char *encrypted_text;
  encrypted_text = malloc(response_size);
  memcpy(encrypted_text, field_back.buffer, ctx.op.params[0].memref.size);

  TEEC_ReleaseSharedMemory(&field_back);

//-----------------------------^^^^^^^^^&&&&&&&&^^^^^^^^^^------------------------
  printf("before add: %p\n", &ctx.sess);
  printf("%d ** %d ** %d\n ", ctx.ctx.fd, ctx.ctx.reg_mem, ctx.ctx.memref_null);
  printf("*** %d ****\n", ctx.sess.session_id);
  ta_ctx_add(&ctx);
  //printf("======ret of ctx add ===== %d\n", ret);

//-----------------------------------------------------------------
  
// everything went good
  ResultMessage res = RESULT_DATA(ResultCode_Ok, response_size, encrypted_text);
  return res;
}

ResultMessage handle_set_key(unsigned char* buf) {

  TEEC_UUID uuid = get_uuid(buf);
  TEEC_Result rc;
  uint32_t err_origin;
  unsigned char* ad;
  unsigned char* cipher;
  unsigned char* tag;

  printf("****************handle set key**********************\n");
//----------------------------------------------------------------------------------
  
  ad = malloc(7);
  memcpy(ad, buf+18, 7);
  //printf("%02X\n", ad[4]);
  cipher = malloc(16);
  memcpy(cipher, buf+25, 16);
  tag = malloc(16);
  memcpy(tag, buf+41, 16);

//-----------------------------^^^^^^^^^&&&&&&&&^^^^^^^^^^------------------------
  printf("uuid before get: %d\n", uuid.timeLow);
  TA_CTX* ta_ctx = ta_ctx_get(uuid);
  printf("address %p and %p and %p\n", &ta_ctx->ctx, &ta_ctx->sess, &ta_ctx->uuid);
  printf("*** %d and %d and %d\n", ta_ctx->ctx.fd, ta_ctx->sess.session_id, ta_ctx->uuid.timeLow);
//-----------------------------------------------------------------
  memset(&ta_ctx->op, 0, sizeof(ta_ctx->op));
	ta_ctx->op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
	ta_ctx->op.params[0].tmpref.buffer = ad;
	ta_ctx->op.params[0].tmpref.size = 7;
	ta_ctx->op.params[1].tmpref.buffer = cipher;
	ta_ctx->op.params[1].tmpref.size = 16;
	ta_ctx->op.params[2].tmpref.buffer = tag;
	ta_ctx->op.params[2].tmpref.size = 16;

  TEEC_Session temp_sess;
  TEEC_Context temp_ctx;
  temp_ctx.fd = ta_ctx->ctx.fd;
  temp_ctx.reg_mem = ta_ctx->ctx.reg_mem;
  temp_ctx.memref_null = ta_ctx->ctx.memref_null;
  printf("%d ** %d ** %d\n ", ta_ctx->ctx.fd, ta_ctx->ctx.reg_mem, ta_ctx->ctx.memref_null);
  printf("*** %d ****\n", ta_ctx->sess.session_id);
  temp_sess.session_id = ta_ctx->sess.session_id;
  temp_sess.ctx = &temp_ctx;

  //printf("session after add %p and %p and %p\n", &(ta_ctx->sess), &ta_ctx->sess, ta_ctx->sess);
  printf("context in sesssion %p\n", ta_ctx->sess.ctx);
  rc = TEEC_InvokeCommand(&temp_sess, 1, &ta_ctx->op, &err_origin);
  check_rc(rc, "TEEC_InvokeCommand", &err_origin);
  if (rc == TEEC_SUCCESS){
    printf("TEEC_SUCCESS\n");
  }
  
// everything went good
  ResultMessage res = RESULT(ResultCode_Ok);
  printf("to ro khoda  3333\n");
  free(ad);
  free(cipher);
  free(tag);
  return res;
}

ResultMessage handle_user_entrypoint(unsigned char* buf) {

  TEEC_UUID uuid = get_uuid(buf);
  TEEC_Result rc;
  uint32_t err_origin;
  printf("****************handle user entrypoint **********************\n");
  //----------------------------------------------------------------------------------
  int j = 0;
  uint32_t index = 0;
  for(int m=17; m>=16; --m){
    index = index + (( buf[m] & 0xFF ) << (8*j));
    ++j;
  }
//-----------------^^^^^^^^^&&&&&&&&^^^^^^^^^^----------
  TA_CTX* ctx1 = ta_ctx_get(uuid);
//-----------------------------------------------------------------
  unsigned char *conn_id_buf;
  conn_id_buf = malloc(32);
  unsigned char *encrypt_buf;
  encrypt_buf = malloc(256);
  unsigned char *tag_buf;
  tag_buf = malloc(256);

  memset(&ctx1->op, 0, sizeof(ctx1->op));
  ctx1->op.params[1].tmpref.buffer = (void *) conn_id_buf;
  ctx1->op.params[1].tmpref.size = 32;
  ctx1->op.params[2].tmpref.buffer = (void *) encrypt_buf;
  ctx1->op.params[2].tmpref.size = 256;
  ctx1->op.params[3].tmpref.buffer = (void *) tag_buf;
  ctx1->op.params[3].tmpref.size = 256;
  ctx1->op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
                TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);


  TEEC_Session temp_sess1;
  TEEC_Context temp_ctx1;
  temp_ctx1.fd = ctx1->ctx.fd;
  temp_ctx1.reg_mem = ctx1->ctx.reg_mem;
  temp_ctx1.memref_null = ctx1->ctx.memref_null;
  
  temp_sess1.session_id = ctx1->sess.session_id;
  temp_sess1.ctx = &temp_ctx1;

  rc = TEEC_InvokeCommand(&temp_sess1, index, &ctx1->op, &err_origin);
  check_rc(rc, "TEEC_InvokeCommand", &err_origin);

  if (rc == TEEC_SUCCESS){

    printf("TEEC_SUCCESS\n");
    printf("%d\n", ctx1->op.params[0].value.a);
    for (int n = 0; n < ctx1->op.params[2].tmpref.size; n++)
		  printf("%02x ", ((uint8_t *)ctx1->op.params[2].tmpref.buffer)[n]);
	  printf("\n");

    for(int i = 0; i < ctx1->op.params[0].value.a; i++){
      uint16_t conn_id = 0;
      unsigned char *handle_encrypt;
      unsigned char *handle_tag;
      handle_encrypt = malloc(16);
      handle_tag = malloc(16);
      int j = 0;
      for(int m = (2*i)+1; m >= (2*i); --m){
        conn_id = conn_id + (( conn_id_buf[m] & 0xFF ) << (8*j));
        ++j;
      }
      memcpy(handle_encrypt, encrypt_buf+(16*i), 16);
      memcpy(handle_tag, tag_buf+(16*i), 16);
      reactive_handle_output(conn_id, handle_encrypt, handle_tag);
      free(handle_encrypt);
      free(handle_tag);
    }
  } 
// everything went good
  ResultMessage res = RESULT(ResultCode_Ok);
  printf("to ro khoda  5555\n");
  free(conn_id_buf);
  free(encrypt_buf);
  free(tag_buf);
  return res;
}

static int is_local_connection(Connection* connection) {
  return connection->to_node == node_number;
}

static void handle_local_connection(Connection* connection,
                                    unsigned char *encrypt, unsigned char *tag) {
    reactive_handle_input(connection->to_sm, connection->conn_id, encrypt, tag);
}

static void handle_remote_connection(Connection* connection,
                                     unsigned char *encrypt, unsigned char *tag) {
    unsigned char payload[100];
    int sockfd; 
    struct sockaddr_in servaddr; 

    char ip[16];

    sprintf(ip, "%d.%d.%d.%d", connection->to_address.u8, connection->to_address.u8[1], 
                connection->to_address.u8[2],connection->to_address.u8[3]);
    printf("IP address is: %s", ip);

	// socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
                    
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(connection->to_port); 
  
    // connect the client socket to server socket 
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the server failed...\n"); 
		    perror("connect");
        exit(0); 
    } 
    else
        printf("connected to the server..\n"); 

    //---------------------------------------------------------------------
    uint16_t conn_id = htons(connection->conn_id);

    bzero(payload, 100);
    payload[0] = command_code_to_u8(CommandCode_RemoteOutput);
    uint32_t htonl_size = htonl(50); //(16 + 2 + 16 + 16)
    memcpy(payload+1, &htonl_size, 4);
    memcpy(payload + 5,connection->to_sm, 16);
    memcpy(payload + 21, &conn_id, 2);
    memcpy(payload + 23, encrypt, 16);
    memcpy(payload + 39, tag, 16);
    
    // and send that buffer to client 
    write(sockfd, payload, sizeof(payload));
    
    bzero(payload, sizeof(payload)); 
    read(sockfd, payload, sizeof(payload));
    ResultCode code = u8_to_result_code(payload[0]);
    if(code == ResultCode_Ok){
      close(sockfd);
    }
}

void reactive_handle_output(uint16_t conn_id, unsigned char* encrypt, unsigned char *tag)
{
  Connection* connection = connections_get(conn_id);

  printf("node_number = %d conn_id = %d port = %d address = %x %x %x %x\n", 
              connection->to_node,
              connection->conn_id, connection->to_port,
              connection->to_address.u8[0], connection->to_address.u8[1],
              connection->to_address.u8[2], connection->to_address.u8[3]);

  if (is_local_connection(connection))
      handle_local_connection(connection, encrypt, tag);
  else
      handle_remote_connection(connection, encrypt, tag);
}

void reactive_handle_input(unsigned char *sm, conn_index conn_id, 
                                        unsigned char *encrypt, unsigned char *tag)
{
  TEEC_Result rc;
  uint32_t err_origin;
  TEEC_UUID uuid = get_uuid(sm);
  printf("****************Reactive Handle Input**********************\n");
//----------------------------------------------------------------------------------
  TA_CTX* ta_ctx = ta_ctx_get(uuid);
//-----------------------------------------------------------------
  memset(&ta_ctx->op, 0, sizeof(ta_ctx->op));
	ta_ctx->op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
	ta_ctx->op.params[0].value.a = conn_id;
	ta_ctx->op.params[1].tmpref.buffer = encrypt;
	ta_ctx->op.params[1].tmpref.size = 16;
	ta_ctx->op.params[2].tmpref.buffer = tag;
	ta_ctx->op.params[2].tmpref.size = 16;

  TEEC_Session temp_sess;
  TEEC_Context temp_ctx;
  temp_ctx.fd = ta_ctx->ctx.fd;
  temp_ctx.reg_mem = ta_ctx->ctx.reg_mem;
  temp_ctx.memref_null = ta_ctx->ctx.memref_null;
 
  temp_sess.session_id = ta_ctx->sess.session_id;
  temp_sess.ctx = &temp_ctx;

  rc = TEEC_InvokeCommand(&temp_sess, 2, &ta_ctx->op, &err_origin);
  check_rc(rc, "TEEC_InvokeCommand", &err_origin);
  if (rc == TEEC_SUCCESS){
    printf("Handle Input TEEC_SUCCESS\n");
  }
}
