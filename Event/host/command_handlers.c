#include "command_handlers.h"
#include<stdio.h>

#include "enclave_utils.h"
#include "addr.h"
#include "connection.h"
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
  
  int j = 0;
  connection.conn_id = 0;
  for(int n = 1; n >= 0; --n){
    connection.conn_id = connection.conn_id + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	
  //----------------------------------------------
  
  j = 0;
  connection.to_sm = 0;
  for(int n = 3; n >= 2; --n){
    connection.to_sm = connection.to_sm + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	
  //---------------------------------------------------------------------

  connection.local = ( m->message->payload[4] & 0xFF );

  //---------------------------------------------------------------------
  j = 0;
  connection.to_port = 0;
  for(int n = 6; n >= 5; --n){
    connection.to_port = connection.to_port + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }
  //--------------------------------------------------------------------
  for(int n = 7; n < 11; n++){
    connection.to_address.u8[n-7] = m->message->payload[n];
  }

  destroy_command_message(m);

  if (!connections_add(&connection))
     return RESULT(ResultCode_InternalError);

  return RESULT(ResultCode_Ok);
}

ResultMessage handler_call_entrypoint(CommandMessage m) {
  
  ResultMessage res;
  int j = 0;
  uint16_t module_id = 0 ;
  for(int n = 1; n >= 0; --n){
    module_id = module_id + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }

  j = 0;
  uint16_t index = 0 ;
  for(int n = 3; n >= 2; --n){
    index = index + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }

  uint32_t data_len = m->message->size - 4;

  switch(index) {
    case Entrypoint_Attest:
      res = handle_attest(m->message->payload, module_id);
      break;
    case Entrypoint_SetKey:
      res = handle_set_key(m->message->payload, module_id);
      break;
    default:
      res = handle_user_entrypoint(m->message->payload, data_len, module_id);
  }

  destroy_command_message(m);

  return res;
}

ResultMessage handler_remote_output(CommandMessage m) {

  uint32_t size = m->message->size - (2 + 2 + 16); // module id + conn id + tag
  conn_index conn_id;
  uint16_t sm_id;
  unsigned char *encrypt;
  encrypt = malloc(size);
  unsigned char *tag;
  tag = malloc(16);
  
  int j = 0;
  sm_id = 0;
  for(int n = 1; n >= 0; --n){
    sm_id = sm_id + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	
  //--------------------------------------------------------------------

  j = 0;
  conn_id = 0;
  for(int n = 3; n >= 2; --n){
    conn_id = conn_id + (( m->message->payload[n] & 0xFF ) << (8*j));
    ++j;
  }	

  memcpy(encrypt, m->message->payload + 4, size);
  memcpy(tag, m->message->payload + 4 + size, 16);

  reactive_handle_input(sm_id, conn_id, encrypt, size, tag);

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
