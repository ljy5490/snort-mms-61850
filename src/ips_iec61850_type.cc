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

// ips_iec61850_func.cc author Jianyu Li <jianyu.li@ait.ac.at>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hashfcn.h"
#include "protocols/packet.h"
#include "profiler/profiler.h"

#include "iec61850.h"

using namespace snort;

static const char* s_name = "iec61850_func";

//-------------------------------------------------------------------------
// func lookup
//-------------------------------------------------------------------------

struct iec61850_func_map_t
{
    const char* name;
    uint8_t func;
};

static iec61850_func_map_t func_map[] =
{
    { "confirmed_request", 0 },
    { "confirmed_response", 1 },
    { "unconfirmed", 3 },
    { "initiate_request", 8 },
    { "initiate_response", 9 },
    { "initiate_error", 10 }
};

static bool get_func(const char* s, long& n)
{
    constexpr size_t max = (sizeof(func_map) / sizeof(iec61850_func_map_t));

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

static THREAD_LOCAL ProfileStats iec61850_func_prof;

class Iec61850FuncOption : public IpsOption
{
public:
    Iec61850FuncOption(uint8_t v) : IpsOption(s_name)
    { func = v; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

public:
    uint8_t func;
};

uint32_t Iec61850FuncOption::hash() const
{
    uint32_t a = func, b = 0, c = 0;

    mix_str(a, b, c, get_name());
    finalize(a,b,c);

    return c;
}

bool Iec61850FuncOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const Iec61850FuncOption& rhs = (const Iec61850FuncOption&)ips;
    return ( func == rhs.func );
}

IpsOption::EvalStatus Iec61850FuncOption::eval(Cursor&, Packet* p)
{
    Profile profile(iec61850_func_prof);

    if ( !p->flow )
        return NO_MATCH;

    if ( !p->is_full_pdu() )
        return NO_MATCH;

    Iec61850FlowData* mfd =
        (Iec61850FlowData*)p->flow->get_flow_data(Iec61850FlowData::inspector_id);

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
    "rule option to check iec61850 function code"

class Iec61850FuncModule : public Module
{
public:
    Iec61850FuncModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &iec61850_func_prof; }

    Usage get_usage() const override
    { return DETECT; }

public:
    uint8_t func;
};

bool Iec61850FuncModule::set(const char*, Value& v, SnortConfig*)
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
    return new Iec61850FuncModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* opt_ctor(Module* m, OptTreeNode*)
{
    Iec61850FuncModule* mod = (Iec61850FuncModule*)m;
    return new Iec61850FuncOption(mod->func);
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

const BaseApi* ips_iec61850_func = &ips_api.base;

