#ifndef SENKO_DNS_MSG_H
#define SENKO_DNS_MSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_MSG_NAME_MAX 256
#define DNS_MSG_MAX_IPV4 32

typedef enum {
    DNS_MSG_OK = 0,
    DNS_MSG_ERR_ARG = -1,
    DNS_MSG_ERR_FORMAT = -2,
    DNS_MSG_ERR_SPACE = -3
} dns_msg_status_t;

typedef enum {
    DNS_BLOCK_ZERO = 0,
    DNS_BLOCK_NXDOMAIN,
    DNS_BLOCK_REFUSED
} dns_block_response_t;

typedef struct {
    char name[DNS_MSG_NAME_MAX];
    uint16_t type;
    uint16_t class_code;
    size_t question_end;
} dns_question_t;

typedef struct {
    uint32_t min_ttl;
    uint32_t ipv4[DNS_MSG_MAX_IPV4];
    size_t ipv4_count;
    int negative;
} dns_response_info_t;

dns_msg_status_t dns_msg_parse_question(const uint8_t *msg, size_t len,
                                        dns_question_t *out);
dns_msg_status_t dns_msg_parse_response_question(const uint8_t *msg, size_t len,
                                                 dns_question_t *out);

dns_msg_status_t dns_msg_build_block(const uint8_t *query, size_t query_len,
                                     dns_block_response_t mode,
                                     uint8_t *out, size_t cap, size_t *out_len);

/* an empty answer with TC set: the real one did not fit, ask again over tcp */
dns_msg_status_t dns_msg_build_truncated(const uint8_t *query, size_t query_len,
                                         uint8_t *out, size_t cap, size_t *out_len);

/* 1 for a name a resolver answers itself instead of asking the internet
   (rfc 6303, 6761, 6762, 8375): the reverse trees of private and special
   addresses, .local and home.arpa. the public resolvers say nxdomain for all
   of them anyway */
int dns_msg_locally_served(const char *name);

dns_msg_status_t dns_msg_response_info(const uint8_t *msg, size_t len,
                                       dns_response_info_t *out);

dns_msg_status_t dns_msg_patch_ttls(uint8_t *msg, size_t len,
                                    uint32_t elapsed_seconds);

dns_msg_status_t dns_msg_clamp_ttls(uint8_t *msg, size_t len,
                                    uint32_t minimum, uint32_t maximum);

#ifdef __cplusplus
}
#endif

#endif
