#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <thread>
#include <pthread.h>

#include <sys/signal.h>

void* runProgram(void* arg)
{
    const char* executable =  (const char*)arg;

    std::string command = "( cat ) | gdb ";
    command.append(executable);
    command.append(" -ex \"break main\" -ex \"run\"");

    char buffer[1024];
    memset(buffer, '\0', 1024);
    int32_t error = system(command.c_str());
}

int main(int argc, char** argv)
{
    remove("gdb.txt");

    pthread_t programThread;
    pthread_create(&programThread, NULL, runProgram, (void*)argv[1]);

    pid_t pid = 0;
    while(pid == 0)
    {
        char pidString[6];
        memset(pidString, '\0', 6);
        FILE* cmd = popen("pidof gdb", "r");
        char* value = fgets(pidString, 6, cmd);
        pid = strtoul(pidString, NULL, 10);
        pclose(cmd);
        usleep(0);
    }

    int32_t error = 0;
    char buffer[1024];
    memset(buffer, '\0', 1024);
    sprintf(buffer, "echo set confirm off > /proc/%d/fd/0", pid);
    error = system(buffer);

    memset(buffer, '\0', 1024);
    sprintf(buffer, "echo set logging on > /proc/%d/fd/0", pid);
    error = system(buffer);

    memset(buffer, '\0', 1024);
    sprintf(buffer, "echo set logging redirect on > /proc/%d/fd/0", pid);
    error = system(buffer);

    memset(buffer, '\0', 1024);
    sprintf(buffer, "echo si > /proc/%d/fd/0", pid);

    int32_t count = 12000;
    while(count--)
    {
        error = system(buffer);
        std::this_thread::yield();
    }

    usleep(1000*1000*1);

    memset(buffer, '\0', 1024);
    sprintf(buffer, "echo quit > /proc/%d/fd/0", pid);
    error = system(buffer);

    return 0;
}
