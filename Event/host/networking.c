#include "networking.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"


#define DEBUG_MSG 0


/* ########## Structs implementation ########## */

/*
  Creates a new Message

  @size: size of payload
  @payload: data read

  @return: Message object (heap allocation)
*/
Message create_message(uint32_t size, unsigned char *payload) {
  Message res = malloc_aligned(sizeof(*res));

  res->size = size;
  res->payload = payload;
  return res;
}


/*
  Prints Message for debug purposes

  @m: Message
*/
#if DEBUG_MSG
void print_message_debug(Message m) {
  printf("Size: %d\n", m->size);
}
#endif


/*
  Destroy a Message (release memory allocated)

  @m: Message
*/
void destroy_message(Message m) {
  if(m->payload != NULL) {
    free(m->payload);
  }

  free(m);
}


/*
  Convert from u8 to Header

  @header: header.

  @return: Header. If the header is invalid (i.e. does not match any enum), returns Header_Invalid
*/
Header u8_to_header(uint8_t header) {
  if(header > Header_Invalid) return Header_Invalid;
  return header;
}


/*
  Convert from Header to u8
  This function is used because Header is stored as int (8 bits)
  and we want to make sure the conversion doesn't produce errors

  @header: Header.

  @return: u8 representation of the header
*/
uint8_t header_to_u8(Header header) {
  return header;
}


/*
  Convert from u8 to ResultCode

  @code: code.

  @return: ResultCode. If the code is invalid (i.e. does not match any enum), returns ResultCode_GenericError
*/
ResultCode u8_to_result_code(uint8_t code) {
  if(code > ResultCode_GenericError) return ResultCode_GenericError;
  return code;
}


/*
  Convert from ResultCode to u8
  This function is used because ResultCode is stored as int (16 bits)
  and we want to make sure the conversion doesn't produce errors

  @code: ResultCode.

  @return: u8 representation of the code
*/
uint8_t result_code_to_u8(ResultCode code) {
  return code;
}


/*
  Creates a new ResultMessage

  @code: ResultCode
  @m: Message

  @return: ResultMessage object (heap allocation)
*/
ResultMessage create_result_message(ResultCode code, Message m) {
  ResultMessage res = malloc_aligned(sizeof(*res));

  res->code = code;
  res->message = m;

  return res;
}


/*
  Prints ResultMessage for debug purposes

  @m: ResultMessage
*/
#if DEBUG_MSG
void print_result_message_debug(ResultMessage m) {
  printf("Result code: %d\n", m->code);
  print_message_debug(m->message);
}
#endif

/*
  Destroy a ResultMessage (release memory allocated)

  @m: ResultMessage
*/
void destroy_result_message(ResultMessage m) {
  destroy_message(m->message);
  free(m);
}


/*
  Convert from u8 to CommandCode

  @code: code.

  @return: CommandCode. If the code is invalid (i.e. does not match any enum), returns CommandCode_Invalid
*/
CommandCode u8_to_command_code(uint8_t code) {
  if(code > CommandCode_Invalid) return CommandCode_Invalid;
  return code;
}


/*
  Convert from CommandCode to u8
  This function is used because CommandCode is stored as int (16 bits)
  and we want to make sure the conversion doesn't produce errors

  @code: CommandCode.

  @return: u8 representation of the code
*/
uint8_t command_code_to_u8(CommandCode code){
  return code;
}


/*
  Creates a new CommandMessage

  @code: CommandCode
  @m: Message

  @return: CommandMessage object (heap allocation)
*/

CommandMessage create_command_message(CommandCode code, Message m) {
  CommandMessage res = malloc_aligned(sizeof(*res));

  res->code = code;
  res->message = m;

  return res;
}


/*
  Prints CommandMessage for debug purposes

  @m: CommandMessage
*/
#if DEBUG_MSG
void print_command_message_debug(CommandMessage m) {
  printf("Command: %d\n", m->code);
  print_message_debug(m->message);
}
#endif


/*
  Destroy a CommandMessage (release memory allocated)

  @m: CommandMessage
*/
void destroy_command_message(CommandMessage m) {
  destroy_message(m->message);
  free(m);
}


/* ########## Read / write functions ########## */

/*
  Get available bytes to read from UART

  @return: number of available bytes to read
*/
size_t available_bytes(void) {
  //return uart_available();
}

/*
  Read a single byte from UART

  @return: byte read
*/
unsigned char read_byte(void) {
  //unsigned char a = uart_read_byte();

  return 0 ;//a;
}


/*
  Write a single byte to UART

  @b: byte to write
*/
void write_byte(unsigned char b) {
  //uart2_write_byte(b);
  //uart_flush();
}


/*
  Performs an "handshake" to initiate transmission (we are the rx)
  Due to issues with timers (loss of bytes) we exchange a first byte with the tx

  Note: It will lock the mutex!!

  In essence:
  - we wait for a byte (going to sleep each time)
  - after we receive the handshake byte, we send back with the same byte and return
  - the tx must wait to send data until the handshake response is received
*/
void handshake(void) {
  while(!available_bytes()) {
    #if USE_MINTIMER
      mintimer_usleep(SLEEP_TIME);
    #else
      //thread_yield();
    #endif
  }
  //mutex_lock(&mutex);
  unsigned char c = read_byte();
  write_byte(c);
}


/*
  Read data from UART

  @buf: buffer previously allocated with an *appropriate* size
  @size: number of bytes to read
  @with_ack: if 1, send and ACK after each read
*/
void read_buf_ack(unsigned char* buf, size_t size, int with_ack) {
  // since RX buffer is limited to 128 bytes, we read only UART_READ_BUF bytes
  // at a time and we send an ACK after each read
  unsigned char ack = Header_ACK;

  size_t size_left = size;
  size_t to_read;

  //LOG_DEBUG("Reading %d bytes..\n", size);

  while(size_left > 0) {
    //to_read = size_left <= UART_READ_BUF ? size_left : UART_READ_BUF;

    //LOG_DEBUG("To read: %d\n", to_read);

    //uart_read(buf, to_read);
    buf += to_read;

    if(with_ack) {
      write_byte(ack);
    }

    size_left -= to_read;
  }
}


/*
  Read data from UART (no ack)

  @buf: buffer previously allocaed with an *appropriate* size
  @size: number of bytes to read
*/
void read_buf(unsigned char* buf, size_t size) {
  read_buf_ack(buf, size, 0);
}


/*
  Write data to UART

  @buf: buffer previously allocaed with an *appropriate* size
  @size: number of bytes to read
*/
void write_buf(unsigned char* buf, size_t size) {
  //uart2_write(buf, size);
  //uart_flush();
}


/*
  Read a u16, performing conversion from network to host byte order

  @return: u16 read
*/
uint16_t read_u16(void) {
  unsigned char buf[2];
  read_buf(buf, 2);

  uint16_t res = ntohs(*(uint16_t *) buf);

  return res;
}


/*
  Write a u16, performing conversion from host to network byte order

  @val: u16 to write
*/
void write_u16(uint16_t val) {
  uint16_t val_n = htons(val);

  write_buf((unsigned char *) &val_n, 2);
}


/*
  Read a message of the format [len u16 - payload]

  @return: Message: caller takes ownership of the data and destroy it
                    using destroy_message when he's done using it
*/
Message read_message(void) {
  uint16_t size = read_u16();
  unsigned char *buf;

  if(size == 0) {
    // nothing to read
    buf = NULL;
  }
  else {
    buf = malloc_aligned(size * sizeof(unsigned char));
    if(buf == NULL) {
      //LOG_ERROR("OOM\n");
      exit(-1);
    }

    read_buf_ack(buf, size, 1);
  }

  return create_message(size, buf);
}


/*
  Write a message of the format [len u16 - payload]

  @m: Message to write
*/
void write_message(Message m) {
  write_u16(m->size);

  if(m->size > 0) {
    write_buf(m->payload, m->size);
  }
}


/*
  Read a message of the format [code u8 - len u16 - payload]

  A 1-byte header is used to recognize different message types with the python wrapper

  Note: it will unlock the mutex!

  @return: ResultMessage: caller takes ownership of the data and destroy it
                    using destroy_result_message when he's done using it
*/
ResultMessage read_result_message(void) {
  uint8_t h = read_byte();
  Header header = u8_to_header(h);

  if (header != Header_Result) {
    //LOG_ERROR("Wrong header");
    exit(-1); // all the other bytes will be garbage, we can't continue execution
  }

  uint8_t code = read_byte();
  Message m = read_message();

  //mutex_unlock(&mutex);

  return create_result_message(u8_to_result_code(code), m);
}


/*
  Write a message of the format [code u8 - len u16 - payload]

  A 1-byte header is used to recognize different message types with the python wrapper
  This operation is mutually exclusive with the "read" functions

  @m: ResultMessage to write
*/
void write_result_message(ResultMessage m) {
  //mutex_lock(&mutex);
  write_byte(header_to_u8(Header_Result));
  write_byte(result_code_to_u8(m->code));
  write_message(m->message);
  //mutex_unlock(&mutex);
}


/*
  Read a message of the format [command u8 - len u16 - payload]

  A 1-byte header is used to recognize different message types with the python wrapper

  Note: It will unlock the mutex!

  @return: CommandMessage: caller takes ownership of the data and destroy it
                    using destroy_command_message when he's done using it
*/
CommandMessage read_command_message(void) {
  uint8_t h = read_byte();
  Header header = u8_to_header(h);

  if (header != Header_Command) {
    //LOG_ERROR("Wrong header");
    exit(-1); // all the other bytes will be garbage, we can't continue execution
  }

  uint8_t code = read_byte();
  Message m = read_message();

  //mutex_unlock(&mutex);

  return create_command_message(u8_to_command_code(code), m);
}


/*
  Write a message of the format [command u8 - len u16 - payload]

  A 1-byte header is used to recognize different message types with the python wrapper
  This operation is mutually exclusive with the "read" functions

  @m: CommandMessage to write
  @ip: ip address - caller must ensure that ip is 4 bytes. e.g. {127,0,0,1}
  @port: port in host byte order
*/
void write_command_message(CommandMessage m, unsigned char* ip, uint16_t port) {
  //mutex_lock(&mutex);
  write_byte(header_to_u8(Header_Command));
  write_buf(ip, 4);
  write_u16(port);
  write_byte(command_code_to_u8(m->code));
  write_message(m->message);
  //mutex_unlock(&mutex);
}
