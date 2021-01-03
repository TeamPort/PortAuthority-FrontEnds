#include "parser.h"

#include <stack>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

enum object_type
{
    LONG,
    STRING,
    CONTAINER,
};

class object
{
    public:
        object(const char* name, object_type type)
        {
            memset(m_attribute, '\0', MAX_BUFFER_SIZE);
            memcpy(m_attribute, name, strlen(name));
            m_type = type;
        }
        object_type get_type(){ return m_type; }
        const char* get_name(){ return m_attribute; };
        virtual long get_long_value(){ assert(0); };
        virtual const char* get_string_value(){ assert(0); };

    private:
        char m_attribute[MAX_BUFFER_SIZE];
        object_type m_type;
};

class long_object: public object
{
    public:
        long_object(const char* name):object(name, LONG){ }
        void set_value(long value){ m_value = value; }
        long get_long_value(){ return m_value; };

    private:
        long m_value;
};

class string_object: public object
{
    public:
        string_object(const char* name):object(name, STRING){ memset(m_value, '\0', MAX_BUFFER_SIZE); }
        void add(char c){ m_value[strlen(m_value)] = c; }
        const char* get_string_value(){ return m_value; };

    private:
        char m_value[MAX_BUFFER_SIZE];
};

class container_object: public object
{
    public:
        container_object(const char* name):object(name, CONTAINER){ }
       ~container_object()
        {
            for(int i = 0; i < m_objects.size(); i++)
            {
                delete m_objects.at(i);
            }
        }
        void add(object* object){ m_objects.push_back(object); }
        int child_count(){ return m_objects.size(); }
        object* at(int index){ return m_objects.at(index); }

    private:
        std::vector<object*> m_objects;
};

void isa::populate(container_object* obj)
{
    for(int i = 0; i < obj->child_count(); i++)
    {
        object* child = obj->at(i);
        switch(child->get_type())
        {
            case STRING:
                assert(!strcmp("name", child->get_name()));
                memcpy(m_name, child->get_string_value(), strlen(child->get_string_value()));
                break;
            case CONTAINER:
                assert(!strcmp("parameters", child->get_name()));
                container_object* container = (container_object*)child;
                populate_specific(container);
                break;
        }
        delete child;
    }
}

void normal::populate_specific(container_object* obj)
{
    assert(!strcmp("parameters", obj->get_name()));
    container_object* container = (container_object*)obj;
    for(int i = 0; i < container->child_count(); i++)
    {
        object* param = container->at(i);
        const char* name = param->get_name();
        if(!strcmp(name, "opcode"))
        {
            m_instr.back()->m_opcode = param->get_long_value();
        }
        else if(!strcmp(name, "mnemonic"))
        {
            memcpy(m_instr.back()->m_mnem, param->get_string_value(), strlen(param->get_string_value()));
        }
        else
        {
            assert(0);
        }
    }
}

void avr_isa::populate_specific(container_object* obj)
{
    normal::populate_specific(obj);
    container_object* container = (container_object*)obj;
    for(int i = 0; i < container->child_count(); i++)
    {
        object* param = container->at(i);
        const char* name = param->get_name();
        if(!strcmp(name, "opcode"))
        {
        }
        else if(!strcmp(name, "mnemonic"))
        {
        }
        else if(!strcmp(name, "mnemonic"))
        {
            m_instr.back()->m_size = param->get_long_value();
        }
        else
        {
            assert(0);
        }
    }
}

enum parse_state
{
    UNKNOWN,
    ATTRIBUTE_NAME,
    VALUE
};

extern "C" 
{
    void parse(const char* json, isa* set)
    {
        Reader reader;
        StringStream ss(json);
        reader.Parse(ss, *set);
    }
}
