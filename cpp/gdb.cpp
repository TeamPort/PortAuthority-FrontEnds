#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <byteswap.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#define GDB_PORT 1234

#define MAX_PACKET_SIZE 0x4000

uint8_t gMachine = 0;
char gLastPacket[MAX_PACKET_SIZE];
bool packetRead(int fd, uint32_t& value)
{
    value = 0;

    char byte;
    uint8_t ndx = 0;
    char buffer[MAX_PACKET_SIZE];
    memset(buffer, '\0', MAX_PACKET_SIZE);

    ssize_t err = 0;
    err = read(fd, &byte, 1); //ack
    while(byte != '#')
    {
        err = read(fd, &byte, 1);
        buffer[ndx++] = byte;
    }

    if(!strcmp(gLastPacket, buffer))
    {
        return false;
    }

    if(strstr(buffer, "T05") != nullptr)
    {
        std::string message(buffer);
        if(gMachine == EM_AVR)
        {
            value = bswap_32(strtol(message.substr(message.find_last_of(":")+1).c_str(), nullptr, 16));
        }
        else if(gMachine == EM_ARM)
        {
            message = message.substr(message.find(";0f:")+4, 8);
            value = bswap_32(strtol(message.c_str(), nullptr, 16));
        }
        else
        {
            message = message.substr(message.find(";20:")+4);
            value = bswap_32(strtol(message.substr(0, message.find_first_of("*")).c_str(), nullptr, 16));
            value = value >> 8;
        }
    }
    else if(strstr(buffer, "$") != nullptr && strstr(buffer, "#"))
    {
        std::string message(buffer);
        value = bswap_32(strtol(message.substr(1, message.length()-1).c_str(), nullptr, 16));
    }

    strcpy(gLastPacket, buffer);

    char checksum[2];
    err = read(fd, checksum, 2);

    return true;
}

bool packetWrite(int fd, uint32_t& address, const char* replay)
{
    ssize_t err = 0;
    err = write(fd, replay, strlen(replay));
    return packetRead(fd, address);
}

uint32_t profileGdb(const char* executable, config configuration, isa* arch)
{
    avr_isa& instructionSet = (avr_isa&)(*arch);

    int32_t fd;
    struct sockaddr_in socketAddress;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd == 0)
        return 0;

    gMachine = configuration.machine;
    socketAddress.sin_family = AF_INET;
    if(configuration.machine == EM_AVR)
    {
        socketAddress.sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        //socketAddress.sin_addr.s_addr = inet_addr("");
        strncpy((char*)&socketAddress.sin_addr.s_addr, (char*)gethostbyname("raspberrypi")->h_addr, sizeof(in_addr_t));
    }
    socketAddress.sin_port = htons(GDB_PORT);

    if(connect(fd, (struct sockaddr*)&socketAddress, sizeof(socketAddress)) == -1)
        return 0;

    uint32_t address = 0;
    if(configuration.machine == EM_AVR)
    {
        //replay sniffed initialization packets
        packetWrite(fd, address, "+$qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+#c9");
        packetWrite(fd, address, "+$Hg0#df");
        packetWrite(fd, address, "+$qTStatus#49");
        packetWrite(fd, address, "+$?#3f");
        packetWrite(fd, address, "+$qfThreadInfo#bb");
        packetWrite(fd, address, "+$qL1160000000000000000#55");
        packetWrite(fd, address, "+$Hc-1#09");
        packetWrite(fd, address, "+$qC#b4");
        packetWrite(fd, address, "+$qAttached#8f");
        packetWrite(fd, address, "+$qOffsets#4b");
        packetWrite(fd, address, "+$qL1160000000000000000#55");
        packetWrite(fd, address, "+$qSymbol::#5b");
    }
    else
    {
        packetWrite(fd, address, "+$qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386#6a");
        packetWrite(fd, address, "+$QProgramSignals:0;1;3;4;6;7;8;9;a;b;c;d;e;f;10;11;12;13;14;15;16;17;18;19;1a;1b;1c;1d;1e;1f;20;21;22;23;24;25;26;27;28;29;2a;2b;2c;2d;2e;2f;30;31;32;33;34;35;36;37;38;39;3a;3b;3c;3d;3e;3f;40;41;42;43;44;45;46;47;48;49;4a;4b;4c;4d;4e;4f;50;51;52;53;54;55;56;57;58;59;5a;5b;5c;5d;5e;5f;60;61;62;63;64;65;66;67;68;69;6a;6b;6c;6d;6e;6f;70;71;72;73;74;75;76;77;78;79;7a;7b;7c;7d;7e;7f;80;81;82;83;84;85;86;87;88;89;8a;8b;8c;8d;8e;8f;90;91;92;93;94;95;96;97;#75");
        packetWrite(fd, address, "+$Hgp0.0#ad");
        packetWrite(fd, address, "+$qXfer:features:read:target.xml:0,fff#7d");
        packetWrite(fd, address, "+$qXfer:features:read:aarch64-core.xml:0,fff#35");
        packetWrite(fd, address, "+$qXfer:features:read:aarch64-fpu.xml:0,fff#d7");
        packetWrite(fd, address, "+$qXfer:auxv:read::0,1000#6b");
        packetWrite(fd, address, "+$QNonStop:0#8c");
        packetWrite(fd, address, "+$qTStatus#49");
        packetWrite(fd, address, "+$qTfV#81");
        packetWrite(fd, address, "+$qTsV#8e");
        packetWrite(fd, address, "+$?#3f");
        packetWrite(fd, address, "+$qXfer:threads:read::0,fff#03");
        packetWrite(fd, address, "+$qAttached#8f");
        packetWrite(fd, address, "+$Hc-1#09");
        packetWrite(fd, address, "+$qOffsets#4b");
        if(configuration.machine == EM_ARM)
        {
            packetWrite(fd, address, "+$G00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b0f7feff0000000014230100100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000#99");
//arm-none-eabi
//            packetWrite(fd, address, "+$G0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010fbfeff0000000030a40000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000#c0");
            packetWrite(fd, address, "+$Z0,12314,4#11");
//            packetWrite(fd, address, "+$Z0,a430,4#0e");
            packetWrite(fd, address, "+$vCont;c#a8");
//            packetWrite(fd, address, "+$z0,a430,4#2e");
            packetWrite(fd, address, "+$z0,12314,4#31");
        }
        else
        {
            packetWrite(fd, address, "+$G0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0f6ffff7f000000c02cfdb77f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000#93");
            packetWrite(fd, address, "+$Z0,402958,4#52");
            packetWrite(fd, address, "+$vCont;c#a8");
            packetWrite(fd, address, "+$z0,402958,4#72");
        }
    }

    uint32_t opcode = 0x0000; //NOP
    uint32_t instructionCount = 0;

    bool keepGoing = false;
    if(configuration.machine == EM_AVR)
    {
        keepGoing = packetWrite(fd, address, "+$s#73");
    }
    else
    {
        keepGoing = packetWrite(fd, address, "+$vCont;s#b8");
    }
    while(keepGoing)
    {
        if(address < configuration.moduleBound)
        {
            uint8_t size = 16;
            char buffer[size];
            memset(buffer, '\0', size);
            sprintf(buffer, "%x", address);

            uint32_t checksum = 0;
            while(size--)
            {
                checksum += buffer[size];
            }
            checksum += 'm';
            checksum += ',';
            checksum += '4';

            //+$mce,4#95
            long ndx = -1;
            sprintf(buffer, "+$m%x,4#%x\n", address, checksum%256);

            const isa_instr* instruction = instructionSet.get_instr(0);
            if(configuration.machine == EM_AVR)
            {
                packetWrite(fd, opcode, buffer);
                ndx = instructionSet.find(avr_decode(opcode));
            }
            if(ndx != -1)
            {
                instruction = instructionSet.get_instr(ndx);
                if(!strcmp(instruction->m_mnem, "break"))
                {
                    //printf("BREAK\n");
                    break;
                }
            }
            else if(configuration.machine != EM_AVR)
            {
                isa_instr dummy = *instruction;
                dummy.m_size = 4;
            }
            else
            {
                //printf("Not found %s 0x%x\n", decode(opcode), opcode);
            }
            instructionCount++;
        }
        sched_yield();
        if(configuration.machine == EM_AVR)
        {
            keepGoing = packetWrite(fd, address, "+$s#73");
        }
        else
        {
            //usleep(1000*32); With Wifi otherwise, weak connection
            keepGoing = packetWrite(fd, address, "+$vCont;s#b8");
        }
    }

    close(fd);
    return instructionCount;
}
