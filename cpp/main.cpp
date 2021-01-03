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
        profileNative(binaryPath, gConfig, (normal*)instructionSet);
    }

    cleanup();

    return 0;
}
