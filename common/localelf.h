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

int32_t getIndexForString(uint8_t* binary, sectionInfo& info, const char* search)
{
    char stringBuffer[info.size];
    memcpy(stringBuffer, &binary[info.offset], info.size);

    char nameBuffer[64];
    memset(nameBuffer, '\0', 64);

    int32_t ndx = 0;
    int32_t cursor = 0;
    uint32_t length = info.size;
    while(length--)
    {
        nameBuffer[cursor] = stringBuffer[ndx];
        if(nameBuffer[cursor] == '\0')
        {
            if(!strcmp(nameBuffer, search))
                return ndx - strlen(nameBuffer);
            memset(nameBuffer, '\0', 64);
            cursor = 0;
        }
        else
        {
            cursor++;
        }
        ndx++;
    }

    return -1;
}

void getStringForIndex(uint8_t* binary, sectionInfo& info, int32_t index, char* buffer, int32_t bufferSize)
{
    char stringBuffer[info.size];
    memcpy(stringBuffer, &binary[info.offset], info.size);

    memset(buffer, '\0', bufferSize);

    int32_t cursor = 0;
    while(stringBuffer[index + cursor] != '\0')
    {
        buffer[cursor] = stringBuffer[index + cursor];
        cursor++;
    }
}