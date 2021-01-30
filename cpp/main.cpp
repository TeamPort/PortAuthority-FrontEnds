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
            const int32_t BOGOMIPS = 5600;
            const float INSTRUCTIONS_PER_SAMPLE = (BOGOMIPS*2)/2.8f;
//            printf("%.0f %.0f\n", instructions*INSTRUCTIONS_PER_SAMPLE, INSTRUCTIONS_PER_SAMPLE);
        }
    }

    cleanup();

    return 0;
}
