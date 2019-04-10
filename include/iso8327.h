#ifndef ISO8327_H
#define ISO8327_H

#include "protocols/packet.h"

#define ISO8327_SPDU_CONNECT 0x0d
#define ISO8327_SPDU_ACCEPT 0x0e
#define ISO8327_SPDU_DATA_GIVE_TOKENS 0x01
#define ISO8327_SPDU_DATA_TRANSFER 0x01

struct iso8327_header_t{
    uint8_t id;
    uint8_t len;
};

struct spdu_parameter_header_t{
    uint8_t type;
    uint8_t len;
};

void iso8327_decode(snort::Packet*, int);

#endif
