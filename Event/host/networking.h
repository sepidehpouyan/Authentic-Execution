#ifndef __NETWORKING_H__
#define __NETWORKING_H__

#include <stddef.h>
#include <stdint.h>

typedef struct message {
  uint32_t size;
  unsigned char *payload;
} *Message;

Message create_message(uint32_t size, unsigned char *payload);
void print_message_debug(Message m);
void test_message(void);
void destroy_message(Message m);

typedef enum {
  Header_Result,
  Header_Command,
  Header_ACK,
  Header_Invalid
} Header;

Header u8_to_header(uint8_t header);
uint8_t header_to_u8(Header header);

typedef enum {
    ResultCode_Ok,
    ResultCode_IllegalCommand,
    ResultCode_IllegalPayload,
    ResultCode_InternalError,
    ResultCode_BadRequest,
    ResultCode_CryptoError,
    ResultCode_GenericError
} ResultCode;

ResultCode u8_to_result_code(uint8_t code);
uint8_t result_code_to_u8(ResultCode code);

typedef struct result {
  ResultCode code;
  Message message;
} *ResultMessage;

#define RESULT(code)  create_result_message(code, create_message(0, NULL))
#define RESULT_DATA(code, size, payload)  create_result_message(code, create_message(size, payload))

ResultMessage create_result_message(ResultCode code, Message m);
void print_result_message_debug(ResultMessage m);
void test_result_message(void);
void destroy_result_message(ResultMessage m);


typedef enum {
    CommandCode_AddConnection,
    CommandCode_CallEntrypoint,
    CommandCode_RemoteOutput,
    CommandCode_LoadSM,
    CommandCode_ModuleOutput,
    CommandCode_Ping,
    CommandCode_RegisterEntrypoint,
    CommandCode_Invalid
} CommandCode;

CommandCode u8_to_command_code(uint8_t code);
uint8_t command_code_to_u8(CommandCode code);

typedef struct command {
  CommandCode code;
  Message message;
} *CommandMessage;

CommandMessage create_command_message(CommandCode code, Message m);
void print_command_message_debug(CommandMessage m);
void test_command_message(void);
void destroy_command_message(CommandMessage m);


size_t available_bytes(void);

unsigned char read_byte(void);
void write_byte(unsigned char b);

void handshake(void);

void read_buf_ack(unsigned char* buf, size_t size, int with_ack);
void read_buf(unsigned char* buf, size_t size);
void write_buf(unsigned char* buf, size_t size);


uint16_t read_u16(void);
void write_u16(uint16_t val);


Message read_message(void);
void write_message(Message m);


ResultMessage read_result_message(void);
void write_result_message(ResultMessage m);


CommandMessage read_command_message(void);
void write_command_message(CommandMessage m, unsigned char* ip, uint16_t port);

#endif
