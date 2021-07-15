
#ifndef NET_IPV4_ADDR_H
#define NET_IPV4_ADDR_H

#include <stdbool.h>
#include <stdint.h>

//#include "byteorder.h"

#define IPV4_ADDR_MAX_STR_LEN       (sizeof("255.255.255.255"))

//====================================================================

typedef union __attribute__((packed)) {
    uint16_t    u16;    /**< 16 bit representation */
    uint8_t      u8[2]; /**< 8 bit representation */
} be_uint16_t;

typedef union __attribute__((packed)) {
    uint32_t    u32;    /**< 32 bit representation */
    uint8_t      u8[4]; /**< 8 bit representation */
    uint16_t    u16[2]; /**< 16 bit representation */
    be_uint16_t b16[2]; /**< big endian 16 bit representation */
} be_uint32_t;

typedef be_uint32_t network_uint32_t;

//==================================================================

typedef union {
    uint8_t u8[4];          /**< as 4 8-bit unsigned integer */
    network_uint32_t u32;   /**< as 32-bit unsigned integer */
} ipv4_addr_t;

static inline bool ipv4_addr_equal(ipv4_addr_t *a, ipv4_addr_t *b)
{
    return (a->u32.u32 == b->u32.u32);
}

char *ipv4_addr_to_str(char *result, const ipv4_addr_t *addr, uint8_t result_len);

ipv4_addr_t *ipv4_addr_from_str(ipv4_addr_t *result, const char *addr);


#endif 
