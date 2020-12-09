#pragma once

#include <deque>
#include <string.h>
#include "rapidjson/reader.h"
using namespace rapidjson;
using namespace std;

class container_object;

#define MAX_BUFFER_SIZE 64

struct isa_instr
{
    public:
        isa_instr(long size, long cycles)
        {
            m_size = size;
            m_cycles = cycles;
        }
        uint64_t m_address;
        long m_opcode;
        long m_cycles;
        long m_size;
        char m_mnem[MAX_BUFFER_SIZE];
        char m_group[MAX_BUFFER_SIZE];
        char m_subgroup[MAX_BUFFER_SIZE];
};

struct isa
{
    isa()
    {
        m_create = false;
    }

    bool String(const char* string, SizeType length, bool copy)
    {
        if(m_buffer != NULL)
        {
            strcpy(m_buffer, string);
            m_buffer = NULL;
        }

        return true;
    }

    bool StartObject()
    {
        if(m_create)
        {
            m_instr.push_back(new isa_instr(2, 1));
        }

        return true;
    }

    virtual bool Key(const char* key, SizeType length, bool copy)
    {
        if(!strcmp(key, "name"))
        {
            m_buffer = m_name;
        }

        return true;
    }

    bool StartArray()
    {
        m_create = true;
        return true;
    }

    bool EndArray(SizeType elementCount)
    {
        m_create = false;
        return true;
    }

            bool Null(){ return true; }
    virtual bool Bool(bool value) = 0;
    virtual bool Int(int value) = 0;
    virtual bool Uint(unsigned value) = 0;
    virtual bool Int64(int64_t value) = 0;
    virtual bool Uint64(uint64_t value) = 0;
    virtual bool Double(double value) = 0;
    virtual bool RawNumber(const char* string, SizeType length, bool copy) = 0;
            bool EndObject(SizeType memberCount){ return true; }

    void populate(container_object* obj);
    const char* get_name(){ return m_name; }
    virtual void populate_specific(container_object* obj) = 0;

    protected:
        char* m_buffer = NULL;
        std::deque<isa_instr*> m_instr;

    private:
        bool m_create;
        char m_name[MAX_BUFFER_SIZE];

};

struct normal: public isa
{
    enum state
    {
        OPCODE,
        CYCLES,
        SIZE,
        UNKNOWN
    };

    state m_state = UNKNOWN;

    virtual bool Uint(unsigned value)
    {
        switch(m_state)
        {
            case OPCODE:
                m_instr.back()->m_opcode = value;
                break;
            case CYCLES:
                m_instr.back()->m_cycles = value;
                break;
            case SIZE:
                m_instr.back()->m_size = value;
                break;
            default:
                break;
        }
        m_state = UNKNOWN;

        return true;
    }

    virtual bool Key(const char* key, SizeType length, bool copy)
    {
        if(!strcmp(key, "opcode"))
        {
            m_state = OPCODE;
        }
        else if(!strcmp(key, "cycles"))
        {
            m_state = CYCLES;
        }
        else if(!strcmp(key, "size"))
        {
            m_state = SIZE;
        }
        else if(!strcmp(key, "mnemonic"))
        {
            m_buffer = m_instr.back()->m_mnem;
        }
        else if(!strcmp(key, "group"))
        {
            m_buffer = m_instr.back()->m_group;
        }
        else if(!strcmp(key, "subgroup"))
        {
            m_buffer = m_instr.back()->m_subgroup;
        }
        else
        {
            isa::Key(key, length, copy);
        }

        return true;
    }

    virtual bool Bool(bool value){ return true; }
    virtual bool Int(int value){ return true; }
    virtual bool Int64(int64_t value){ return true; }
    virtual bool Uint64(uint64_t value){ return true; }
    virtual bool Double(double value){ return true; }
    virtual bool RawNumber(const char* string, SizeType length, bool copy){ return true; }

    long size(){ return m_instr.size(); }
    long find(const char* mnemonic)
    {
        int32_t ndx = -1;
        int32_t count = size();
        while(count--)
        {
            if(!strcmp(get_mnemonic(count), mnemonic))
            {
                ndx = count;
                break;
            }
        }

        return ndx;
    };
    virtual void populate_specific(container_object* obj);
    long get_opcode(int32_t ndx){ return m_instr.at(ndx)->m_opcode; };
    const  char* get_mnemonic(int32_t ndx){ return m_instr.at(ndx)->m_mnem; };
    const  char* get_group(int32_t ndx){ return m_instr.at(ndx)->m_group; };
    const  char* get_subgroup(int32_t ndx){ return m_instr.at(ndx)->m_subgroup; };
const isa_instr* get_instr(int32_t ndx){ return m_instr.at(ndx); };
};

struct x86_isa: public normal
{
};

struct avr_isa: public normal
{
public:
    virtual void populate_specific(container_object* obj);
};

struct aarch64_isa: public normal
{
};
