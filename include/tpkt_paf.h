// tpkt_paf.h author Jianyu Li

#ifndef TPKT_PAF__H
#define TPKT_PAF__H

// Protocol-Aware Flushing (PAF) code for the mms preprocessor.

#include "stream/stream_splitter.h"

#define GID_DPX 144

#define MODBUS_BAD_LENGTH 1
#define MODBUS_BAD_PROTO_ID 2
#define MODBUS_RESERVED_FUNCTION 3

enum tpkt_paf_state_t
{
    TPKT_PAF_STATE__VERSION,
    TPKT_PAF_STATE__RESERVED,
    TPKT_PAF_STATE__LENGTH_1,
    TPKT_PAF_STATE__LENGTH_2,
    TPKT_PAF_STATE__SET_FLUSH
};

class TpktSplitter : public snort::StreamSplitter
{
public:
    TpktSplitter(bool);

    Status scan(snort::Flow*, const uint8_t* data, uint32_t len, uint32_t flags,
        uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    tpkt_paf_state_t state;
    uint16_t tpkt_length;
};

#endif

