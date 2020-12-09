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
#ifdef __aarch64__
    int32_t arg = 0;
    std::string command;
    command += "./suspend.sh";
    while(arg < subprocessCachedArgc)
    {
        command += " ";
        command += subprocessCachedArgv[arg++];
    }

    FILE* process = popen(command.c_str(), "r");

    char pidStr[6];
    memset(pidStr, '\0', 6);
    char* cursor = pidStr;

    int fd = fileno(process);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    ssize_t bytes = 0;
    while(bytes >= 0)
    {
        usleep(1000*100);
        bytes = read(fd, cursor, 1);
        cursor++;
    }

    *pid = atoi(pidStr);
#else
    posix_spawn(pid, executable, NULL, NULL, subprocessCachedArgv, NULL);
#endif
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

int8_t disassemble(char* mnem, int32_t size, uint64_t value, int machine)
{
    int32_t byte = 0;
    if(machine == EM_AARCH64)
    {
        const char* disasm = arm64_decode((uint32_t)value);
        memset(mnem, '\0', size);
        strcpy(mnem, disasm);
        byte = 4;
    }
    else
    {
        ud_t u;
        ud_init(&u);
        ud_set_syntax(&u, UD_SYN_ATT);
        ud_set_mode(&u, machine == EM_X86_64 ? 64: 32);
    
        const int32_t INSTRUCTION_LENGTH_MAX = 7;
        uint8_t instructions[INSTRUCTION_LENGTH_MAX];
        for(int32_t i = 0; i < INSTRUCTION_LENGTH_MAX; i++)
        {
            instructions[i] = value&0xFF;
            value >>= 8;
        }
    
        bool invalid = true;
        while(invalid && (byte <= INSTRUCTION_LENGTH_MAX))
        {
            byte++;
            ud_set_input_buffer(&u, instructions, byte);
            ud_disassemble(&u);
            invalid = strcmp(ud_insn_asm(&u), "invalid ") == 0;
        }

        memset(mnem, '\0', size);
        const char* disasm = ud_insn_asm(&u);
        uint8_t chr = 0;
        char c = disasm[0];
        while(c != '\0' && c != ' ')
        {
            mnem[chr++] = c;
            c = disasm[chr];
        }
    }

    return byte;
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
