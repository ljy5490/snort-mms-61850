// iec61850.cc author Jianyu Li <jianyu.li@ait.ac.at>

#include "iec61850.h"

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

#define IEC61850_GID 256
#define IEC61850_SID 1

static const char* s_name = "iec61850";
static const char* s_help = "iec61850 mms inspector";

static THREAD_LOCAL ProfileStats iec61850PerfStats;

static THREAD_LOCAL SimpleStats iec61850stats;

//-------------------------------------------------------------------------
// flow stuff
//-------------------------------------------------------------------------


unsigned Iec61850FlowData::inspector_id = 0;

void Iec61850FlowData::init(){
    inspector_id = FlowData::create_flow_data_id();
}

Iec61850FlowData::Iec61850FlowData() : FlowData(inspector_id){
    reset();
}

Iec61850FlowData::~Iec61850FlowData(){
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------


class Iec61850 : public Inspector
{
public:
    Iec61850(uint16_t port, uint16_t max);

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

Iec61850::Iec61850(uint16_t p, uint16_t m)
{
    port = p;
    max = m;
    
}

void Iec61850::show(SnortConfig*)
{
    LogMessage("%s config:\n", s_name);
    LogMessage("    port = %d\n", port);
    LogMessage("    max = %d\n", max);
}


void Iec61850::eval(Packet* p)
{
    //cout << p->dsize << endl;
    //cout << p->is_cooked() << endl;
    //DetectionEngine::queue_event(IEC61850_GID, 2);
    //cout << iec61850stats.total_packets << endl;
    //

    Iec61850FlowData *dfd = (Iec61850FlowData *)p->flow->get_flow_data(Iec61850FlowData::inspector_id);

    if(!dfd){
        dfd = new Iec61850FlowData;
	p->flow->set_flow_data(dfd);
    }

    //printf("------------Hello IEC61850\n");
    tpkt_decode(p);

    ++iec61850stats.total_packets;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter iec61850_params[] =
{
    { "port", Parameter::PT_PORT, nullptr, nullptr,
      "port to check" },

    { "max", Parameter::PT_INT, "0:65535", "0",
      "maximum payload before alert" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const RuleMap iec61850_rules[] =
{
    { IEC61850_SID, "too much data sent to port" },
    { 2, "{'control_action':'tapup'}"},
    { 0, nullptr }
};

class Iec61850Module : public Module
{
public:
    Iec61850Module() : Module(s_name, s_help, iec61850_params)
    { }

    unsigned get_gid() const override
    { return IEC61850_GID; }

    const RuleMap* get_rules() const override
    { return iec61850_rules; }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&iec61850stats; }

    ProfileStats* get_profile() const override
    { return &iec61850PerfStats; }

    bool set(const char*, Value& v, SnortConfig*) override;

    Usage get_usage() const override
    { return INSPECT; }

public:
    uint16_t port;
    uint16_t max;
};

bool Iec61850Module::set(const char*, Value& v, SnortConfig*)
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
{ return new Iec61850Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* iec61850_ctor(Module* m)
{
    Iec61850Module* mod = (Iec61850Module*)m;
    return new Iec61850(mod->port, mod->max);
}

static void iec61850_dtor(Inspector* p)
{
    delete p;
}

static void iec61850_init()
{
    Iec61850FlowData::init();
}

static const InspectApi iec61850_api
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
    iec61850_init, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    iec61850_ctor,
    iec61850_dtor,
    nullptr, // ssn
    nullptr  // reset
};

//extern const BaseApi* ips_pkt_num;
extern const BaseApi* ips_iec61850_func;

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &iec61850_api.base,
    ips_iec61850_func,
    nullptr
};

