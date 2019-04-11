#include "tpkt.h"
#include "iec61850.h"
#include "cotp.h"

#include "detection/detection_engine.h"
#include "protocols/packet.h"

using namespace snort;

#define TPKT_VERSION 0x03
#define TPKT_RESERVED 0x00

struct tpkt_header_t{
    uint8_t version;
    uint8_t reserved;
    uint8_t length1;
    uint8_t length2;
};

void tpkt_decode(Packet *p){
    const tpkt_header_t *header;
    header = (const tpkt_header_t *)p->data;

    if(header->version != TPKT_VERSION){
	//DetectionEngine::queue_event()
        //printf("TPKT:bad version number");
    }

    if(header->reserved != TPKT_RESERVED){
	//DetectionEngine::queue_event()
        //printf("TPKT:bad reserved");
    }

    cotp_decode(p, 4);
    //printf("%d %d\n", header->length1, header->length2);
    return;
}
