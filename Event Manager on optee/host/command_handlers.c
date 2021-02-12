#include "command_handlers.h"
#include<stdio.h>

#include "enclave_utils.h"
#include "addr.h"
#include "connection.h"
//#include "byteorder.h"
#include "utils.h"

#if USE_PERIODIC_EVENTS
  #include "periodic_event.h"
#endif

ResultMessage handler_load_sm(CommandMessage m) {
  ResultMessage res = load_enclave(m->message->payload, m->message->size);
  destroy_command_message(m);
  return res;
}

ResultMessage handler_add_connection(CommandMessage m) {
  Connection connection;

  int size = m->message->size;
  printf("######################## Add Connection Started ####################\n");
  printf("%d\n",size);
  
  int j = 0;
  connection.conn_id = 0;
  for(int n=1; n>=0; --n){
    connection.conn_id = connection.conn_id + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	
  printf("conn id : %d\n", connection.conn_id);
  //----------------------------------------------
  for(int i = 0; i < 16; i++){
    connection.to_sm[i] = m->message->payload[i+2];
  }

  //--------------------------------------------------------------------
  j = 0;
  connection.to_node = 0;
  for(int n=19; n>=18; --n){
    connection.to_node = connection.to_node + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	
  printf("port number : %d\n", connection.to_node);
  //---------------------------------------------------------------------
  j = 0;
  connection.to_port = 0;
  for(int n=21; n>=20; --n){
    connection.to_port = connection.to_port + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	
  printf("port number : %d\n", connection.to_port);
  //--------------------------------------------------------------------
  for(int n = 22; n < 26; n++){
    connection.to_address.u8[n-22] = m->message->payload[n];
  }

  destroy_command_message(m);

  if (!connections_add(&connection))
     return RESULT(ResultCode_InternalError);

  return RESULT(ResultCode_Ok);
}

ResultMessage handler_call_entrypoint(CommandMessage m) {

  printf("############### Handle Call Entrypoint Started ############\n");
  
  ResultMessage res;
  int j = 0;
  uint16_t index = 0 ;
  for(int n=17; n>=16; --n){
    index = index + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	
  printf("index : %d\n", index);

  switch(index) {
    case Entrypoint_SetKey:
      res = handle_set_key(m->message->payload);
      break;
    default:
      res = handle_user_entrypoint(m->message->payload);
  }

  destroy_command_message(m);

  return res;
}

ResultMessage handler_remote_output(CommandMessage m) {

  conn_index conn_id;
  unsigned char *sm_id;
  sm_id = malloc(16);
  unsigned char *encrypt;
  encrypt = malloc(16);
  unsigned char *tag;
  tag = malloc(16);
  
  memcpy(sm_id, m->message->payload, 16);

  int j = 0;
  conn_id = 0;
  for(int n=17; n>=16; --n){
    conn_id = conn_id + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	

  memcpy(encrypt, m->message->payload + 18, 16);
  memcpy(tag, m->message->payload + 34, 16);

  reactive_handle_input(sm_id, conn_id, encrypt, tag);

  free(sm_id);
  free(encrypt);
  free(tag);
  destroy_command_message(m);

  return RESULT(ResultCode_Ok);
}



ResultMessage handler_ping(CommandMessage m) {
  destroy_command_message(m);
  return RESULT(ResultCode_Ok);
}

ResultMessage handler_register_entrypoint(CommandMessage m) {

#if USE_PERIODIC_EVENTS
  PeriodicEvent event;
  ParseState *state = create_parse_state(m->message->payload,
                           m->message->size);

   // The payload format is [module entry frequency]
  if (!parse_int(state, &event.module))
     return RESULT(ResultCode_IllegalPayload);
  if (!parse_int(state, &event.entry))
     return RESULT(ResultCode_IllegalPayload);

  uint32_t *freq;
  if (!parse_raw_data(state, sizeof(uint32_t), (uint8_t **)&freq))
    return RESULT(ResultCode_IllegalPayload);

  event.frequency = REVERSE_INT32(*freq);
  event.counter = 0;

  free_parse_state(state);
  destroy_command_message(m);

  periodic_event_add(&event);
#else
  destroy_command_message(m);
#endif

  return RESULT(ResultCode_Ok);
}
