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

// ips_dpx_func.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "dpx.h"

using namespace snort;

static const char* s_name = "dpx_func";

//-------------------------------------------------------------------------
// func lookup
//-------------------------------------------------------------------------

struct dpx_func_map_t
{
    const char* name;
    uint8_t func;
};

static dpx_func_map_t func_map[] =
{
    { "read_coils", 1 },
    { "read_discrete_inputs", 2 },
    { "read_holding_registers", 3 },
    { "read_input_registers", 4 },
    { "write_single_coil", 5 },
    { "write_single_register", 6 },
    { "read_exception_status", 7 },
    { "diagnostics", 8 },
    { "get_comm_event_counter", 11 },
    { "get_comm_event_log", 12 },
    { "write_multiple_coils", 15 },
    { "write_multiple_registers", 16 },
    { "report_slave_id", 17 },
    { "read_file_record", 20 },
    { "write_file_record", 21 },
    { "mask_write_register", 22 },
    { "read_write_multiple_registers", 23 },
    { "read_fifo_queue", 24 },
    { "encapsulated_interface_transport", 43 }
};

static bool get_func(const char* s, long& n)
{
    constexpr size_t max = (sizeof(func_map) / sizeof(dpx_func_map_t));

    for ( size_t i = 0; i < max; ++i )
    {
        if ( !strcmp(s, func_map[i].name) )
        {
            n = func_map[i].func;
            return true;
        }
    }
    return false;
}

//-------------------------------------------------------------------------
// func option
//-------------------------------------------------------------------------

static THREAD_LOCAL ProfileStats dpx_func_prof;

class DpxFuncOption : public IpsOption
{
public:
    DpxFuncOption(uint8_t v) : IpsOption(s_name)
    { func = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t func;
};

uint32_t DpxFuncOption::hash() const
{
    uint32_t a = func, b = 0, c = 0;

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool DpxFuncOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const DpxFuncOption& rhs = (const DpxFuncOption&)ips;
    return ( func == rhs.func );
}

IpsOption::EvalStatus DpxFuncOption::eval(Cursor&, Packet* p)
{
    Profile profile(dpx_func_prof);

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    DpxFlowData* mfd =
        (DpxFlowData*)p->flow->get_flow_data(DpxFlowData::inspector_id);

    if ( mfd and func == mfd->mms_session_data.type )
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~", Parameter::PT_STRING, nullptr, nullptr,
      "function code to match" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check dpx function code"

class DpxFuncModule : public Module
{
public:
    DpxFuncModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &dpx_func_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t func;
};

bool DpxFuncModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~") )
        return false;

    long n;

    if ( v.strtol(n) )
        func = (uint8_t)n;

    else if ( get_func(v.get_string(), n) )
        func = (uint8_t)n;

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new DpxFuncModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    DpxFuncModule* mod = (DpxFuncModule*)m;
    return new DpxFuncOption(mod->func);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi ips_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    opt_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_dpx_func = &ips_api.base;

