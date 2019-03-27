//--------------------------------------------------------------------------
// Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
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
// dpx.cc author Russ Combs <rcombs@sourcefire.com>

#include "dpx.h"

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "flow/flow.h"

#include "tpkt_paf.h"
#include "tpkt.h"

#include <fstream>
#include <iostream>
#include <algorithm>
#include <list>
#include <string>
#include <cstring>
#include <typeinfo>

using namespace snort;
using namespace std;
//using namespace rapidjson;

#define DPX_GID 256
#define DPX_SID 1

static const char* s_name = "dpx";
static const char* s_help = "dynamic inspector example";

static THREAD_LOCAL ProfileStats dpxPerfStats;

static THREAD_LOCAL SimpleStats dpxstats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------


unsigned DpxFlowData::inspector_id = 0;

void DpxFlowData::init(){
    inspector_id = FlowData::create_flow_data_id();
}

DpxFlowData::DpxFlowData() : FlowData(inspector_id){
    reset();
}

DpxFlowData::~DpxFlowData(){
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------


class Dpx : public Inspector
{
public:
    Dpx(uint16_t port, uint16_t max);

    void show(SnortConfig*) override;
    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    //{ return new ModbusSplitter(c2s); }
    { return new TpktSplitter(c2s); }


private:
    uint16_t port;
    uint16_t max;

    //list<int> control_action_list;
};

Dpx::Dpx(uint16_t p, uint16_t m)
{
    port = p;
    max = m;
    
}

void Dpx::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    port = %d\n", port);
    LogMessage("    max = %d\n", max);
}


void Dpx::eval(Packet* p)
{
    //cout << p->dsize << endl;
    //cout << p->is_cooked() << endl;
    //DetectionEngine::queue_event(DPX_GID, 2);
    //cout << dpxstats.total_packets << endl;
    //

    DpxFlowData *dfd = (DpxFlowData *)p->flow->get_flow_data(DpxFlowData::inspector_id);

    if(!dfd){
        dfd = new DpxFlowData;
	p->flow->set_flow_data(dfd);
    }

    tpkt_decode(p);

    ++dpxstats.total_packets;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter dpx_params[] =
{
    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port to check" },

    { "max", Parameter::PT_INT, "0:65535", "0",
      "maximum payload before alert" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap dpx_rules[] =
{
    { DPX_SID, "too much data sent to port" },
    { 2, "{'control_action':'tapup'}"},
    { 0, nullptr }
};

class DpxModule : public Module
{
public:
    DpxModule() : Module(s_name, s_help, dpx_params)
    { }

    unsigned get_gid() const override
    { return DPX_GID; }

    const RuleMap* get_rules() const override
    { return dpx_rules; }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&dpxstats; }

    ProfileStats* get_profile() const override
    { return &dpxPerfStats; }

    bool set(const char*, Value& v, SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }

public:
    uint16_t port;
    uint16_t max;
};

bool DpxModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("port") )
        port = v.get_long();

    else if ( v.is("max") )
        max = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DpxModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* dpx_ctor(Module* m)
{
    DpxModule* mod = (DpxModule*)m;
    return new Dpx(mod->port, mod->max);
}

static void dpx_dtor(Inspector* p)
{
    delete p;
}

static void dpx_init()
{
    DpxFlowData::init();
}

static const InspectApi dpx_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    //IT_NETWORK,
    //IT_PROBE,
    IT_SERVICE,
    //PROTO_BIT__UDP,
    //PROTO_BIT__TCP,
    PROTO_BIT__PDU,
    //PROTO_BIT__ANY_TYPE,
    nullptr, // buffers
    nullptr, // service
    dpx_init, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    dpx_ctor,
    dpx_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dpx_api.base,
    nullptr
};

