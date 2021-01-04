#include <stdint.h>
#include <sstream>
#include <string.h>

#include <iomanip>

#include <libelf.h>
#include "localelf.h"

char* subprocessCachedArgv[64];

int32_t cachedArgc = 0;
char argvStorage[1024];
char* cachedArgv[64];

int32_t subprocessCachedArgc = 0;
char subprocessArgvStorage[1024];

struct config
{
    bool useGdb = false;
    int32_t hitcount = 1;
    uint8_t machine = 0;
    uint64_t pltSize = 0;
    uint64_t pltStart = 0;
    uint64_t textSize = 0;
    uint64_t moduleBound = 0;
    uint64_t profilerAddress = 0;
    uint64_t exitAddress = 0;
};

config gConfig;

std::string gOutput;
int32_t gFileNumber = 0;
std::stringstream gStamp;
int32_t gArchiveNumber = 0;
const int32_t SCRATCH_BUFFER_SIZE = 256;

void dumpToFile(const char* content)
{
    char buffer[SCRATCH_BUFFER_SIZE];
    memset(buffer, '\0', SCRATCH_BUFFER_SIZE);
    sprintf(buffer, "%s-%d", gStamp.str().c_str(), gFileNumber);

    FILE* output = fopen(buffer, "w");
    fwrite(content, strlen(content), 1, output);
    fclose(output);
}

void writeHeader(uint64_t textSize)
{
    char buffer[SCRATCH_BUFFER_SIZE];
    memset(buffer, '\0', SCRATCH_BUFFER_SIZE);
    sprintf(buffer, "{\"triple\":\"x86_64-pc-linux-gnu\",\"size\":%ld,\"run\":[\n", textSize);
    gOutput.append(buffer);
}

void writeFooter()
{
    // Dummy extra value to avoid complex last comma logic
    char buffer[SCRATCH_BUFFER_SIZE];
    memset(buffer, '\0', SCRATCH_BUFFER_SIZE);
    sprintf(buffer, "{\"a\":\"0x%lx\",\"o\":\"0x%lx\",\"m\":\"%s\"}]}", (uint64_t)0x0, (uint64_t)0, "NOP");
    gOutput.append(buffer);
}

void dumpToArchive()
{
    char buffer[SCRATCH_BUFFER_SIZE];
    memset(buffer, '\0', SCRATCH_BUFFER_SIZE);

    int32_t file = 0;
    std::string command = "cat ";
    while(file <= gFileNumber)
    {
        memset(buffer, '\0', SCRATCH_BUFFER_SIZE);
        sprintf(buffer, "%s-%d", gStamp.str().c_str(), file);
        command.append(buffer);
        command.append(" ");
        file++;
    }

    const char* notify = "\e[93mCompressing result files\e[0m\n";
    fwrite(notify, strlen(notify), 1, stderr);

    command.append("| gzip > ");
    memset(buffer, '\0', SCRATCH_BUFFER_SIZE);
    sprintf(buffer, "%s_%d.gz", gStamp.str().c_str(), gArchiveNumber);
    command.append(buffer);
    int result = system(command.c_str());

    command.clear();
    command = "rm ";
    memset(buffer, '\0', SCRATCH_BUFFER_SIZE);
    sprintf(buffer, "%s-*", gStamp.str().c_str());
    command.append(buffer);
    result = system(command.c_str());

    gFileNumber = 0;
    gArchiveNumber++;
}

#include "parser.cpp"
#include "disavr.cpp"
#include "disarm64.cpp"

isa* instructionSet = nullptr;
char* subprocessStoragePointer = nullptr;
const char* binaryPath = nullptr;

FILE* executable = nullptr;

bool preamble(int argc, char** argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    cachedArgc = argc;
    char* storagePointer = argvStorage;
    while(argc--)
    {
        cachedArgv[argc] = storagePointer;
        int32_t length = strlen(argv[argc]);
        strcat(storagePointer, argv[argc]);
        storagePointer+=(length+1);
    }

    subprocessStoragePointer = subprocessArgvStorage;
    binaryPath = cachedArgv[1];

    const char* breakFunction = "";
    const char* endFunction = "";
    uint64_t breakAddress = 0;
    uint64_t endAddress = 0;

    // Parse remaining arguments
    int32_t arg = cachedArgc;
    while(arg--)
    {
        if(!strcmp(cachedArgv[arg], "--break"))
        {
            breakFunction = cachedArgv[arg+1];
        }
        else if(!strcmp(cachedArgv[arg], "--end"))
        {
            endFunction = cachedArgv[arg+1];
        }
        else if(!strcmp(cachedArgv[arg], "--break-at-address"))
        {
            breakAddress = strtol(cachedArgv[arg+1], NULL, 16);
        }
        else if(!strcmp(cachedArgv[arg], "--end-at-address"))
        {
            endAddress = strtol(cachedArgv[arg+1], NULL, 16);
        }
        else if(!strcmp(cachedArgv[arg], "--hit-count"))
        {
            gConfig.hitcount = strtol(cachedArgv[arg+1], NULL, 10);
        }
        else if(!strcmp(cachedArgv[arg], "--arg"))
        {
            subprocessCachedArgv[subprocessCachedArgc] = subprocessStoragePointer;
            int32_t length = strlen(cachedArgv[arg+1]);
            strcat(subprocessStoragePointer, cachedArgv[arg+1]);
            subprocessStoragePointer+=(length+1);
            subprocessCachedArgc++;
        }
    }

    subprocessCachedArgv[subprocessCachedArgc] = subprocessStoragePointer;
    int32_t length = strlen(binaryPath);
    strcat(subprocessStoragePointer, binaryPath);
    subprocessStoragePointer+=(length+1);
    subprocessCachedArgc++;

    int32_t i = 0;
    int32_t j = subprocessCachedArgc-1;
    while(i < j)
    {
        auto temp = subprocessCachedArgv[i];
        subprocessCachedArgv[i] = subprocessCachedArgv[j];
        subprocessCachedArgv[j] = temp;
        i++;
        j--;
    }

    bool arch64 = false;
    uint64_t textStart = 0;

    executable = fopen(binaryPath, "r");
    if(executable)
    {
        fseek(executable, 0, SEEK_END);
        int32_t size = ftell(executable);
        rewind(executable);
        uint8_t* binary = (uint8_t*)malloc(size);
        size_t read = fread(binary, 1, size, executable);
        if(read != size) return false;

        arch64 = binary[4] == 0x2;
        uint64_t offset = 0;
        uint16_t headerSize = 0;
        uint16_t numHeaders = 0;
        uint64_t entryAddress = 0;
        uint16_t stringsIndex = 0;

        if(arch64)
        {
            Elf64_Ehdr* header = (Elf64_Ehdr*)binary;
            headerSize = header->e_shentsize;
            numHeaders = header->e_shnum;
            offset = header->e_shoff;
            stringsIndex = header->e_shstrndx;
            gConfig.machine = header->e_machine;
            entryAddress = header->e_entry;
        }
        else
        {
            Elf32_Ehdr* header = (Elf32_Ehdr*)binary;
            headerSize = header->e_shentsize;
            numHeaders = header->e_shnum;
            offset = header->e_shoff;
            stringsIndex = header->e_shstrndx;
            gConfig.machine = header->e_machine;
            entryAddress = header->e_entry;
        }

        gConfig.useGdb = gConfig.machine == EM_AVR || gConfig.machine == EM_ARM;

        if(breakFunction == "" && breakAddress == 0)
        {
            const char* warning = "\e[93mUsing default entry point\e[0m\n";
            fwrite(warning, strlen(warning), 1, stderr);

            breakFunction =  gConfig.machine == EM_AVR ? "__vectors": "main";
        }

        if(endFunction == "" && endAddress == 0)
        {
            const char* warning = "\e[93mUsing default exit point\e[0m\n";
            fwrite(warning, strlen(warning), 1, stderr);

            endFunction =  gConfig.machine == EM_AVR ? "__stop_program": "_fini";
        }

        sections sect;
        int32_t ndx = 0;
        const int16_t totalHeaders = numHeaders;
        sect.si = (sectionInfo*)malloc(sizeof(sectionInfo)*numHeaders);
        while(numHeaders--)
        {
            if(headerSize == sizeof(Elf64_Shdr))
            {
                Elf64_Shdr* section = (Elf64_Shdr*)(binary + offset);
                sect.si[ndx].index = section->sh_name;
                sect.si[ndx].address = section->sh_addr;
                sect.si[ndx].type = section->sh_type;
                sect.si[ndx].offset = section->sh_offset;
                sect.si[ndx].size = section->sh_size;
            }
            else
            {
                Elf32_Shdr* section = (Elf32_Shdr*)(binary + offset);
                sect.si[ndx].index = section->sh_name;
                sect.si[ndx].address = section->sh_addr;
                sect.si[ndx].type = section->sh_type;
                sect.si[ndx].offset = section->sh_offset;
                sect.si[ndx].size = section->sh_size;
            }
            offset += headerSize;
            ndx++;
        }

        int32_t pltIndex = 0;
        int32_t textIndex = 0;
        int32_t symbolsIndex = 0;
        int32_t stringTableIndex = 0;

        ndx = 0;
        numHeaders = totalHeaders;

        int32_t init        = getIndexForString(binary, sect.si[stringsIndex], ".init");
        int32_t text        = getIndexForString(binary, sect.si[stringsIndex], ".text");
        int32_t symbolTable = getIndexForString(binary, sect.si[stringsIndex], ".symtab");
        int32_t stringTable = getIndexForString(binary, sect.si[stringsIndex], ".strtab");

        while(numHeaders--)
        {
            if(sect.si[ndx].index == init)
            {
                pltIndex = ndx+1;
                sect.si[pltIndex].plt = true;
            }

            sect.si[ndx].text        = sect.si[ndx].index == text;
            sect.si[ndx].symbols     = sect.si[ndx].index == symbolTable;
            sect.si[ndx].stringTable = sect.si[ndx].index == stringTable;
            if(sect.si[ndx].symbols)
                symbolsIndex = ndx;
            if(sect.si[ndx].stringTable)
                stringTableIndex = ndx;
            if(sect.si[ndx].text)
                textIndex = ndx;
            ndx++;
        }

        gConfig.pltSize = sect.si[pltIndex].size;
        gConfig.pltStart = sect.si[pltIndex].address;
        gConfig.textSize = sect.si[textIndex].size;
        textStart = sect.si[textIndex].address;
        gConfig.profilerAddress = textStart; //reasonable default
        ndx = 0;

        uint8_t type = 0;
        uint32_t name = 0;
        uint64_t symbolSize = 0;
        uint64_t address = 0;
        uint64_t highestAddress = 0;
        int32_t symbols = sect.si[symbolsIndex].size / (headerSize == sizeof(Elf64_Shdr) ? sizeof(Elf64_Sym): sizeof(Elf32_Sym));  

        char buffer[256];
        while(symbols--)
        {
            if(headerSize == sizeof(Elf64_Shdr))
            {
                Elf64_Sym* symbols = (Elf64_Sym*)(binary + sect.si[symbolsIndex].offset);
                type = ELF64_ST_TYPE(symbols[ndx].st_info);
                name = symbols[ndx].st_name;
                symbolSize = symbols[ndx].st_size;
                address = symbols[ndx].st_value;
            }
            else
            {
                Elf32_Sym* symbols = (Elf32_Sym*)(binary + sect.si[symbolsIndex].offset);
                type = ELF32_ST_TYPE(symbols[ndx].st_info);
                name = symbols[ndx].st_name;
                symbolSize = symbols[ndx].st_size;
                address = symbols[ndx].st_value;
            }

            if(type == 2) //function
            {
                highestAddress = highestAddress < address ? address: highestAddress;
                highestAddress += symbolSize;
                getStringForIndex(binary, sect.si[stringTableIndex], name, buffer, 256);

                if(breakAddress == 0 && !strcmp(breakFunction, buffer))
                {
                    gConfig.profilerAddress = address;
                }

                if(endAddress == 0 && !strcmp(endFunction, buffer))
                {
                    gConfig.exitAddress = address;
                }
            }
            ndx++;
        }

        if(breakAddress != 0) gConfig.profilerAddress = breakAddress;
        if(endAddress != 0) gConfig.exitAddress = endAddress;

        if(highestAddress == 0) highestAddress = ~0;

        gConfig.moduleBound = highestAddress;
        free(sect.si);
        free(binary);
    }

    char* json = nullptr;
    FILE* library = nullptr;
    if(gConfig.machine == EM_AVR)
    {
        library = fopen("../common/avr.json", "r");
        instructionSet = new avr_isa();
    }
    else if(gConfig.machine == EM_ARM)
    {
        // TODO
    }
    else if(gConfig.machine == EM_AARCH64)
    {
        library = fopen("../common/aarch64.json", "r");
        instructionSet = new aarch64_isa();
    }
    else
    {
        library = fopen("../common/x86.json", "r");
        instructionSet = new x86_isa();
    }

    if(library)
    {
        fseek(library, 0, SEEK_END);
        int32_t size = ftell(library);
        rewind(library);
        json = (char*)malloc(size);
        size_t read = fread(json, 1, size, library);
        if(read != size) return -1;
    }
    parse(json, instructionSet);
    free(json);

    time_t t = time(nullptr);
    gStamp << "../../../";
    gStamp << std::put_time(std::localtime(&t), "%Y-%m-%d%X");

    writeHeader(gConfig.textSize);

    return true;
}

int32_t numLines = 0;
const int32_t MAX_FILES  = 1;
const int32_t MAX_LINES  = 12000000;
void outputInstruction(uint64_t instructionAddress, uint32_t value, const char* mnem)
{
    char buffer[SCRATCH_BUFFER_SIZE];
    memset(buffer, '\0', SCRATCH_BUFFER_SIZE);
    sprintf(buffer, "{\"a\":\"0x%lx\",\"o\":\"0x%x\",\"m\":\"%s\"},\n", instructionAddress, value, mnem);
    gOutput.append(buffer);
    numLines++;

    if(numLines == MAX_LINES)
    {
        if(gFileNumber == (MAX_FILES-1))
        {
            writeFooter();
        }

        dumpToFile(gOutput.c_str());
        gOutput.clear();
        numLines = 0;
        gFileNumber++;
    }

    if(gFileNumber == MAX_FILES)
    {
        dumpToArchive();
        writeHeader(gConfig.textSize);
    }
}

void cleanup()
{
    writeFooter();
    dumpToFile(gOutput.c_str());
    dumpToArchive();

    delete instructionSet;
    instructionSet = nullptr;

    fclose(executable);
}
