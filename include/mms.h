#ifndef MMS_H
#define MMS_H

#include "protocols/packet.h"

void mms_decode(snort::Packet*, uint8_t*, int);

#endif
