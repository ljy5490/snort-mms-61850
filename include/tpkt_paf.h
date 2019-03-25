//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2011-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

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

