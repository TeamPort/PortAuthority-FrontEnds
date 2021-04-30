#include <spawn.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <byteswap.h>

#include "native.h"

#include <chrono>
using namespace std::chrono;

#ifdef __aarch64__
#define BREAK 0xD4200000 //aarch64 breakpoint instruction
#else
#define BREAK 0xCC //x86 breakpoint instruction
#endif

uint32_t profileNative(const char* executable, config configuration, normal* arch)
{
    uint64_t moduleLow = 0;
    uint64_t moduleHigh = 0;

    bool transition = false;
    microseconds untracked = microseconds{0};
    microseconds startTransition = duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch());
    microseconds endTransition = startTransition;

    pid_t pid = 0;
    int32_t status = 0;
    user_regs_struct registers;

#ifdef __aarch64__
    iovec buffer;
    buffer.iov_base = &registers;
    buffer.iov_len = sizeof(registers);
    iovec* registerBuffer = &buffer;
#else
    user_regs_struct* registerBuffer = &registers;
#endif

    size_t size = 8;
    uint8_t binary[8];

    FILE* reopen = fopen(executable, "r");
    if(fread(binary, 1, size, reopen) != size) return 0;

    int machine = EM_AARCH64;
    bool arch64 = binary[4] == 0x2;
#ifndef __aarch64__
    if(arch64)
    {
        machine = EM_X86_64;
    }
    else
    {
        machine = EM_386;
    }
#endif

    spawnProcess(&pid, executable);

    microseconds startProfile = duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch());

    ud_t u;
    ud_init(&u);
    ud_set_syntax(&u, UD_SYN_ATT);
    ud_set_mode(&u, arch64 ? 64: 32);
    const int32_t INSTRUCTION_LENGTH_MAX = 7;
    uint8_t instructions[INSTRUCTION_LENGTH_MAX];

    int32_t total = 0;
    uint64_t next = 0;
    bool fromBranch = false;
    uint32_t instructionCount = 0;

    if(configuration.sampling)
    {
        ptrace(PTRACE_SEIZE, pid, NULL, NULL);
        ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
        waitpid(pid, &status, WSTOPPED);
        while(WIFSTOPPED(status))
        {
            uint64_t instructionAddress = 0;
#if defined( __aarch64__)
            ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, registerBuffer);
            instructionAddress = registers.pc;
#else
            ptrace(PTRACE_GETREGS, pid, NULL, registerBuffer);
            instructionAddress = registers.rip;
#endif
            if(instructionAddress == configuration.exitAddress)
            {
                //natural program termination
                break;
            }

            if(instructionAddress < configuration.moduleBound)
            {
                instructionCount++;
            }

            system_clock::time_point start = system_clock::now();
            system_clock::time_point sync = start + nanoseconds(SAMPLE_INTERVAL_IN_MICROSECONDS*1000);
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            system_clock::time_point now = system_clock::now();
            while(now < sync)
            {
                now = system_clock::now();
            }

            ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
            waitpid(pid, &status, WSTOPPED);

            ptrace(PTRACE_GETREGS, pid, NULL, registerBuffer);

            uint64_t stack = registers.rsp;
            uint64_t address = registers.rip;

            int32_t count = gConfig.perSample;
            uint8_t instructions[sizeof(long)];
            while(address && count > 0)
            {
                total++;
                if(total % 1000 == 0) printf("Processing...\n");

                uint8_t byte = 0;
                bool found = false;
                int32_t iterations = 1;

                const int32_t MAX_ITERATIONS = 256;
                while(!found && iterations < MAX_ITERATIONS)
                {
                    byte = 0;
                    long data = ptrace(PTRACE_PEEKDATA, pid, address - sizeof(long)*iterations, nullptr);
                    memcpy(instructions, &data, sizeof(long));
                    while(!found && byte < sizeof(long))
                    {
                        found = instructions[byte++] == 0xc3; // ret
                    }

                    if(!found)
                    {
                        iterations++;
                    }
                }

                if(iterations > MAX_ITERATIONS) break;

                uint64_t disassembleAddress = address - sizeof(long)*iterations + byte;
                int64_t diff = address - disassembleAddress;
                while(count > 0 && diff >= 0)
                {
                    uint64_t value = ptrace(PTRACE_PEEKDATA, pid, disassembleAddress, nullptr);

                    const int32_t size = 16;
                    char mnem[size];
                    uint8_t byte = disassemble(mnem, size, value, machine);
                    disassembleAddress += byte;
                    diff = address-disassembleAddress;

                    long ndx = arch->find(mnem);
                    if(ndx != -1)
                    {
                        if(instructionAddress < configuration.moduleBound)
                        {
                            instructionCount++;
                        }
                        instructionCount++;
                        count--;
                        outputInstruction(instructionAddress, bswap_32(value), mnem);
                    }
                }

                const int32_t MAX_DISTANCE = 256;

                uint64_t current = stack;
                while(count > 0 && (current-stack) < MAX_DISTANCE)
                {
                    uint64_t value = ptrace(PTRACE_PEEKDATA, pid, current, nullptr);
                    if(value >= stack)
                    {
                        stack = value;
                        address = ptrace(PTRACE_PEEKDATA, pid, current + sizeof(uint64_t), nullptr);
                        break;
                    }
                    current += sizeof(uint64_t);
                }

                if((current-stack) >= MAX_DISTANCE)
                {
                    break;
                }
            }
        }
    }
    else
    {
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        waitpid(pid, &status, WSTOPPED);

        ptrace(PTRACE_CONT, pid, NULL, NULL);
        //_start causes the process to stop
        waitpid(pid, &status, WSTOPPED);

        long data = setBreakInstruction(pid, configuration.profilerAddress);

        //run to break
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        waitpid(pid, &status, WSTOPPED);

        clearBreakInstruction(pid, configuration.profilerAddress, data);
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        waitpid(pid, &status, WSTOPPED);

        uint64_t ip = 0;
#if defined( __aarch64__)
        ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, registerBuffer);
        ip = registers.pc;
#else
        ptrace(PTRACE_GETREGS, pid, NULL, registerBuffer);
        ip = registers.rip;
#endif

        int32_t count = configuration.hitcount-1;
        while(count)
        {
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            waitpid(pid, &status, WSTOPPED);

#if defined( __aarch64__)
            ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, registerBuffer);
            ip = registers.pc;
#else
            ptrace(PTRACE_GETREGS, pid, NULL, registerBuffer);
            ip = registers.rip;
#endif

            if(ip == configuration.profilerAddress)
            {
                count--;
            }
        }

        char modulesPath[32];
        sprintf(modulesPath,"/proc/%d/maps", pid);

        char* line = nullptr;
        FILE* modules = fopen(modulesPath, "r");
        if(modules)
        {
            size_t length = 0;
            while(getline(&line, &length, modules) != -1)
            {
                string module(line);
                if(module.find("libopencv_core") != -1)
                {
                    char* token = strtok(line, " ");
                    token = strtok(nullptr, " ");
                    if(strchr(token, 'x') != nullptr) //executable permission
                    {
                        char range[64];
                        token = strtok(line, " ");
                        strcpy(range, token);
                        range[strlen(token)] = '\0';
                        token = strtok(range, "-");
                        moduleLow = strtoll(token, nullptr, 16);
                        token = strtok(nullptr, "-");
                        moduleHigh = strtoll(token, nullptr, 16);
                        break;
                    }
                }
            }
        }

        while(WIFSTOPPED(status))
        {
            uint64_t instructionAddress = 0;
#if defined( __aarch64__)
            ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, registerBuffer);
            instructionAddress = registers.pc;
#else
            ptrace(PTRACE_GETREGS, pid, NULL, registerBuffer);
            instructionAddress = registers.rip;
#endif
            if(instructionAddress == configuration.exitAddress)
            {
                //natural program termination
                break;
            }
            //need better protections here for code that does not exit cleanly, without exit()
            if(instructionAddress < configuration.moduleBound)
            {
                uint64_t value = ptrace(PTRACE_PEEKDATA, pid, instructionAddress, nullptr);
                if(!transition)
                {
                    if(startTransition != endTransition)
                    {
                        endTransition = duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch());
                        untracked += endTransition-startTransition;
                    }
                }
                transition = true;

                if(shouldSkip(instructionAddress, next, value, configuration.pltStart, configuration.pltStart + configuration.pltSize))
                {
                    uint64_t value = setBreakInstruction(pid, next);

                    //run to break
                    ptrace(PTRACE_CONT, pid, NULL, NULL);
                    waitpid(pid, &status, WSTOPPED);

                    clearBreakInstruction(pid, next, value);
                }

                const int32_t size = 16;
                char mnem[size];
                uint8_t byte = disassemble(mnem, size, value, machine);
                next = instructionAddress + byte;
                fromBranch = strstr("BLR", mnem) != nullptr;

                long ndx = arch->find(mnem);
                if(ndx != -1)
                {
                    outputInstruction(instructionAddress, bswap_32(value), mnem);

                    const isa_instr* instruction = arch->get_instr(ndx);
                    isa_instr modified = *instruction;
                    modified.m_size = byte;
                }
                else
                {
                    //printf("Not found: %s\n", mnem);
                }
                instructionCount++;
            }
            else
            {
                if(transition)
                {
                    startTransition = duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch());
                }
                transition = false;

                if(fromBranch)
                {
                    uint64_t value = setBreakInstruction(pid, next);

                    //run to break
                    ptrace(PTRACE_CONT, pid, NULL, NULL);
                    waitpid(pid, &status, WSTOPPED);

                    clearBreakInstruction(pid, next, value);
                }

                if(instructionAddress >= moduleLow && instructionAddress <= moduleHigh)
                {
                }
            }

            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            waitpid(pid, &status, WSTOPPED);
        }
    }

    kill(pid, SIGKILL);

    microseconds endProfile = duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch());
    //printf("Runtime (ms): %ld Untracked: %ld\n", duration_cast<milliseconds>(endProfile-startProfile).count(), duration_cast<milliseconds>(untracked).count());

    return instructionCount;
}
