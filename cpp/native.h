#include <string>
#include <spawn.h>

#if defined( __aarch64__)
typedef iovec register_buffer;
#else
typedef user_regs_struct register_buffer;
#endif

#ifdef __aarch64__
#define BREAK 0xD4200000 //aarch64 breakpoint instruction
#else
#define BREAK 0xCC //x86 breakpoint instruction
#endif

register_buffer* setupRegisters(user_regs_struct* registers)
{
#if defined(__aarch64__)
    iovec* buffer = new iovec();
    buffer->iov_base = registers;
    buffer->iov_len = sizeof(user_regs_struct);
    iovec* registerBuffer = buffer;
#else
    user_regs_struct* registerBuffer = registers;
#endif

    return registerBuffer;
}

void releaseRegisters(register_buffer** registers)
{
#ifdef __aarch64__
    delete *registers;
    *registers = nullptr;
#endif
}

void spawnProcess(pid_t* pid, const char* executable)
{
    posix_spawn(pid, executable, NULL, NULL, subprocessCachedArgv, NULL);
}

long setBreakInstruction(pid_t pid, uint64_t address)
{
    long data = ptrace(PTRACE_PEEKDATA, pid, address, NULL);

#ifndef __aarch64__
    const int32_t INSTRUCTION_LENGTH_MAX = 7;
    uint8_t instructions[INSTRUCTION_LENGTH_MAX];

    memcpy(instructions, &data, INSTRUCTION_LENGTH_MAX);
    uint8_t bytes[sizeof(long)];
    memset(bytes, BREAK, sizeof(long));
    ptrace(PTRACE_POKEDATA, pid, address, *(long*)bytes);
#else
    ptrace(PTRACE_POKEDATA, pid, address, BREAK);
#endif

    return data;
}

void clearBreakInstruction(pid_t pid, uint64_t address, long data)
{
    user_regs_struct registers;
    register_buffer* registerBuffer = setupRegisters(&registers);

    //replace instruction
    ptrace(PTRACE_POKEDATA, pid, address, data);

#ifndef __aarch64__
    ptrace(PTRACE_GETREGS, pid, NULL, registerBuffer);
    registerBuffer->rip = address;
    ptrace(PTRACE_SETREGS, pid, NULL, registerBuffer);
#else
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, registerBuffer);
    registers.pc = address;
    ptrace(PTRACE_SETREGSET, pid, NULL, registerBuffer);
#endif

    releaseRegisters(&registerBuffer);
}

bool shouldSkip(uint64_t instructionAddress, uint64_t next, uint64_t value, uint64_t pltStart, uint64_t pltEnd)
{
    bool skip = false;
#ifdef __aarch64__
    const char* test = arm64_decode((uint32_t)value);
    skip = (next != 0 && ((instructionAddress >= pltStart && instructionAddress <= pltEnd) || !strcmp(test, "LDAXR") || !strcmp(test, "STLXR")));
#else
    skip = (next != 0 && (instructionAddress >= pltStart && instructionAddress <= pltEnd));
#endif

    return skip;
}
