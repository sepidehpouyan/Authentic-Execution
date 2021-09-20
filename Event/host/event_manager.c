#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h>

#include "networking.h"
#include "command_handlers.h"

#define MAX 200000


ResultMessage process_message(CommandMessage m) {
  switch (m->code) {
    case CommandCode_AddConnection:
      return handler_add_connection(m);// seconddddd

    case CommandCode_CallEntrypoint:
      return handler_call_entrypoint(m); // third "set-key" and // fourth call // attest

    case CommandCode_RemoteOutput:
      return handler_remote_output(m); // 

    case CommandCode_LoadSM:
      return handler_load_sm(m); // firsttttt

    case CommandCode_Ping:
      return handler_ping(m);

    case CommandCode_RegisterEntrypoint:
      return handler_register_entrypoint(m);

    default: // CommandCode_Invalid
      return NULL;
  }
}

// Function designed for reading data on the socket 
int event_manager_run(int sd, struct sockaddr_in address, int addrlen,
           int *client_socket, int index) {

    unsigned char buff[MAX]; 
    unsigned char data[MAX];
    unsigned char *payload;
    int n = 0; 
    int ret = 1;
    int size = 0;
    int byte_to_read = 6;
 
    bzero(buff, MAX);
    bzero(data, MAX);

    //Check if it was for closing , and also read the incoming message   
    while((n < byte_to_read)){
      
      ret = read(sd, buff, sizeof(buff));
    	if(ret == 0) {
        //Somebody disconnected , get his details and print  
        //getpeername(sd , (struct sockaddr*)&address ,(socklen_t*)&addrlen);   
        //printf("Host disconnected , ip %s , port %d \n", 
                  //inet_ntoa(address.sin_addr) , ntohs(address.sin_port));   
                         
        //Close the socket and mark as 0 in list for reuse 
        close(sd);  
        client_socket[index] = 0;
        return 0;
      }
      if (ret > 0){
    	  memcpy(data + n, buff, ret);
    	  n = n + ret;
    	  size = 0;
        //==========================================================
        CommandCode code = u8_to_command_code(data[0]);
        if(code == 3) {
          if(n > 5) {
    		    int j = 0;
    		    for(int m= 4; m>=1; --m) {
    			    size = size + (( data[m] & 0xFF ) << (8*j));
    			    ++j;
    		    }		
    	    }
    	    byte_to_read = 1 + 4 + size;
        }
        else {
          if(n > 3) {
    		    int j = 0;
    		    for(int m = 2; m>=1; --m) {
    			    size = size + (( data[m] & 0xFF ) << (8*j));
    			    ++j;
    		    }		
    	    }
    	    byte_to_read = 1 + 2 + size;
        }
        //=----------------------------------------------------------------
      } // ret > 0
    }// while loop
    
    payload = malloc(size);
    CommandCode code = u8_to_command_code(data[0]);
    if(code == 3){
      memcpy(payload, data+5, size);
    }
    else {
      memcpy(payload, data+3, size);
    }
    Message msg = create_message(size, payload);
    CommandMessage m = create_command_message(code, msg);
    ResultMessage res = process_message(m);

    if(res != NULL) {
      bzero(buff, MAX);
      buff[0] = result_code_to_u8(res->code);
      Message msg = res->message;
      uint16_t response_size = msg->size;
      uint16_t htons_size = htons(response_size);
      memcpy(buff+1, &htons_size, 2);
      memcpy(buff+3, msg->payload, msg->size);
      // and send that buffer to client 
      write(sd, buff, sizeof(buff));
      destroy_result_message(res);
    }

    return 0;

   
}