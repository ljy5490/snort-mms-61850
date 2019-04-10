#ifndef ACSE_H
#define ACSE_H

#include "protocols/packet.h"

void acse_decode(snort::Packet*, uint8_t*, int);

#endif
