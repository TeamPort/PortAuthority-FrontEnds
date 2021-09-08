#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include <deque>
#include <map>

#include <fstream>
#include <iostream>

#include "../common/shared.h"

#ifndef __aarch64__
#define SAMPLE_INTERVAL_IN_MICROSECONDS 50
#else
#define SAMPLE_INTERVAL_IN_MICROSECONDS 4
#endif

#include "native.cpp"
#include "gdb.cpp"

int main(int argc, char** argv)
{
    if(!preamble(argc, argv)) return -1;

    if(gConfig.useGdb)
    {
        profileGdb(binaryPath, gConfig, instructionSet);
    }
    else
    {
        char buffer[128];
        memset(buffer, '\0', 128);
        FILE* f = popen("cat /proc/cpuinfo | grep -i bogomips", "r");
        if(fgets(buffer, sizeof(buffer), f) == nullptr) return -1;
        pclose(f);

        float mips = atof(strstr(buffer, ":") + 1);

#ifndef __aarch64__
        const float CYCLES_PER_INSTRUCTION = 2.8f;
#else
        const float CYCLES_PER_INSTRUCTION = 1.2f;
#endif
        gConfig.perSample = (mips*SAMPLE_INTERVAL_IN_MICROSECONDS)/CYCLES_PER_INSTRUCTION;
        uint64_t instructions = profileNative(binaryPath, gConfig, (normal*)instructionSet);
        printf("%lu\n", instructions);
    }

    cleanup();

    return 0;
}
