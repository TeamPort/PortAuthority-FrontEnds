struct sectionInfo
{
    uint32_t type;
    uint32_t index;
    uint64_t address;
    uint64_t offset;
    uint64_t size;
    bool plt;
    bool text;
    bool symbols;
    bool stringTable;
};

struct sections
{
    uint32_t numSections;
    sectionInfo* si;
};

#include "elfutils.h"