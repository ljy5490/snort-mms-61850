#ifndef COTP_H
#define COTP_H

#include "protocols/packet.h"

#define COTP_CONNECTION_REQUEST 0xe0
#define COTP_CONNECTION_CONFIRM 0xd0
#define COTP_DATA 0xf0

struct cotp_header_t{
    uint8_t header_len;
    uint8_t code;
};

struct cotp_data_header_t{
    uint8_t header_len;
    uint8_t code;
    uint8_t eof_tpdu_num;
};

void cotp_decode(snort::Packet*, int);

#endif
