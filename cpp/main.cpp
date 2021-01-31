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
#define SAMPLE_INTERVAL_IN_MICROSECONDS 2
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
        uint64_t instructions = profileNative(binaryPath, gConfig, (normal*)instructionSet);
        if(gConfig.sampling)
        {
#ifndef __aarch64__
            const float BOGOMIPS = 5600;
            const float CYCLES_PER_INSTRUCTION = 2.8f;
#else
            const float BOGOMIPS = 62.5;
            const float CYCLES_PER_INSTRUCTION = 1.2f;
#endif
            const float INSTRUCTIONS_PER_SAMPLE = (BOGOMIPS*SAMPLE_INTERVAL_IN_MICROSECONDS)/CYCLES_PER_INSTRUCTION;
//            printf("%.0f %.0f\n", instructions*INSTRUCTIONS_PER_SAMPLE, INSTRUCTIONS_PER_SAMPLE);
        }
    }

    cleanup();

    return 0;
}
