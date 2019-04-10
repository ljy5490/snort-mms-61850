#ifndef ISO8823_H
#define ISO8823_H

#include "protocols/packet.h"

#define ISO8823_CP_TYPE 0x01
#define ISO8823_CPA_PPDU 0x02
#define ISO8823_CPC_TYPE 0x03

void iso8823_decode(snort::Packet*, int, int);

#endif
