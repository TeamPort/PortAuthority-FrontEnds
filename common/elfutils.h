static int32_t getIndexForString(uint8_t* binary, uint64_t size, uint64_t offset, const char* search)
{
    char stringBuffer[size];
    memcpy(stringBuffer, &binary[offset], size);

    char nameBuffer[64];
    memset(nameBuffer, '\0', 64);

    int32_t ndx = 0;
    int32_t cursor = 0;
    uint32_t length = size;
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

static void getStringForIndex(uint8_t* binary, uint64_t size, uint64_t offset, int32_t index, char* buffer, int32_t bufferSize)
{
    char stringBuffer[size];
    memcpy(stringBuffer, &binary[offset], size);

    memset(buffer, '\0', bufferSize);

    int32_t cursor = 0;
    while(stringBuffer[index + cursor] != '\0')
    {
        buffer[cursor] = stringBuffer[index + cursor];
        cursor++;
    }
}
